// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! OIDC SSO provider (§8 v2). Authorization Code + PKCE against a discovered IdP; the id_token is
//! verified (JWKS signature + nonce + audience + expiry) by `openidconnect`, then the configured
//! role claim is read from the verified token and mapped to a role.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use base64::Engine;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AsyncHttpClient, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde_json::Value;

use waf_governance::rbac::{map_claims_to_role, Role};

use crate::config::OidcConfig;
use crate::error::{Error, Result};

/// The client `from_provider_metadata` builds: the authorization endpoint is set, the token and
/// userinfo endpoints are whatever discovery returned (so `exchange_code` is fallible).
type DiscoveredClient =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

/// A discovered OIDC provider + its config, ready to drive the login flow.
pub struct OidcProvider {
    client: DiscoveredClient,
    http: IdpHttp,
    scopes: Vec<String>,
    role_claim: String,
    role_map: Vec<(String, Role)>,
    default_role: Option<Role>,
}

/// The start of a login flow: where to send the browser, plus the per-flow secrets to persist.
pub struct AuthStart {
    pub authorize_url: String,
    pub state: String,
    pub pkce_verifier: String,
    pub nonce: String,
}

/// The verified identity from a callback: a username and the mapped role.
pub struct VerifiedIdentity {
    pub username: String,
    pub role: Role,
}

impl OidcProvider {
    /// Discover the IdP (`<issuer>/.well-known/openid-configuration`) and build the client. Called
    /// once at boot; a bad issuer / unreachable IdP is a boot-fatal config error.
    pub async fn discover(cfg: &OidcConfig) -> Result<Self> {
        let secret = cfg
            .client_secret
            .clone()
            .ok_or_else(|| Error::Config("oidc: client_secret (or WAF_CP_OIDC_CLIENT_SECRET) is required".into()))?;
        let issuer = IssuerUrl::new(cfg.issuer_url.clone())
            .map_err(|e| Error::Config(format!("oidc issuer_url: {e}")))?;
        let http = IdpHttp::new().map_err(|e| Error::Config(format!("oidc http client: {e}")))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .map_err(|e| Error::Config(format!("oidc discovery failed: {e}")))?;
        let redirect = RedirectUrl::new(cfg.redirect_url.clone())
            .map_err(|e| Error::Config(format!("oidc redirect_url: {e}")))?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(cfg.client_id.clone()),
            Some(ClientSecret::new(secret)),
        )
        .set_redirect_uri(redirect);
        Ok(Self {
            client,
            http,
            scopes: cfg.scopes.clone(),
            role_claim: cfg.role_claim.clone(),
            role_map: cfg.role_map.iter().map(|e| (e.claim.clone(), e.role)).collect(),
            default_role: cfg.default_role,
        })
    }

    /// Build the IdP authorization URL + the CSRF state / PKCE verifier / nonce to persist for the
    /// callback.
    pub fn authorize(&self) -> AuthStart {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = self.client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for s in &self.scopes {
            req = req.add_scope(Scope::new(s.clone()));
        }
        let (url, state, nonce) = req.set_pkce_challenge(pkce_challenge).url();
        AuthStart {
            authorize_url: url.to_string(),
            state: state.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            nonce: nonce.secret().clone(),
        }
    }

    /// Exchange the `code` for tokens, verify the id_token, and map the role claim → a role. Errors
    /// (bad code, verification failure, no role match) are returned as messages for a 401/403.
    pub async fn verify_callback(
        &self,
        code: String,
        pkce_verifier: String,
        nonce: String,
    ) -> std::result::Result<VerifiedIdentity, String> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| format!("token exchange: {e}"))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.http)
            .await
            .map_err(|e| format!("token exchange failed: {e}"))?;

        let id_token = token_response.id_token().ok_or("no id_token in response")?;
        let claims = id_token
            .claims(&self.client.id_token_verifier(), &Nonce::new(nonce))
            .map_err(|e| format!("id_token verification failed: {e}"))?;

        // Username: preferred_username, else email.
        let username = claims
            .preferred_username()
            .map(|u| u.as_str().to_string())
            .or_else(|| claims.email().map(|e| e.as_str().to_string()))
            .ok_or("id_token has no preferred_username or email")?;

        // Role: read the configured claim from the (verified) raw payload, map to a role.
        let jwt = serde_json::to_value(id_token)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .ok_or("could not read raw id_token")?;
        let payload = decode_jwt_payload(&jwt).ok_or("could not decode id_token payload")?;
        let claim_values = extract_claim_values(&payload, &self.role_claim);
        let role = map_claims_to_role(&claim_values, &self.role_map)
            .or(self.default_role)
            .ok_or("no role: token matched no role_map entry and no default_role is set")?;

        Ok(VerifiedIdentity { username, role })
    }
}

/// The HTTP transport for the IdP calls (discovery, token, JWKS), over the workspace's reqwest: TLS
/// is the process-level ring provider installed in main. It never follows redirects — the
/// `openidconnect` guidance against SSRF. A named type rather than a closure, so the returned future
/// is `Send` for every lifetime (the callback runs inside an axum handler).
struct IdpHttp(reqwest::Client);

impl IdpHttp {
    fn new() -> reqwest::Result<Self> {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map(Self)
    }
}

impl<'c> AsyncHttpClient<'c> for IdpHttp {
    type Error = reqwest::Error;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<HttpResponse, reqwest::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.0.execute(reqwest::Request::try_from(request)?).await?;
            let status = response.status();
            let headers = response.headers().clone();
            let mut out = HttpResponse::new(response.bytes().await?.to_vec());
            *out.status_mut() = status;
            *out.headers_mut() = headers;
            Ok(out)
        })
    }
}

/// Decode the (already signature-verified) middle segment of a compact JWT to a JSON object.
fn decode_jwt_payload(jwt: &str) -> Option<Value> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Read a claim's value(s): a JSON string → one value; an array of strings → each; else empty.
pub fn extract_claim_values(payload: &Value, claim: &str) -> Vec<String> {
    match payload.get(claim) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_string_and_array_claims() {
        let p = json!({ "role": "admin", "groups": ["a", "b"], "n": 5 });
        assert_eq!(extract_claim_values(&p, "role"), vec!["admin"]);
        assert_eq!(extract_claim_values(&p, "groups"), vec!["a", "b"]);
        assert!(extract_claim_values(&p, "n").is_empty());
        assert!(extract_claim_values(&p, "missing").is_empty());
    }

    #[test]
    fn decode_payload_of_a_jwt() {
        // header.payload.signature — payload = {"groups":["waf-admins"]} url-safe base64.
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"groups":["waf-admins"],"preferred_username":"kim"}"#);
        let jwt = format!("aaa.{payload}.bbb");
        let decoded = decode_jwt_payload(&jwt).expect("decode");
        assert_eq!(extract_claim_values(&decoded, "groups"), vec!["waf-admins"]);
        assert_eq!(decoded["preferred_username"], "kim");
    }

    #[test]
    fn role_mapping_with_default() {
        let map = vec![("waf-admins".to_string(), Role::Admin)];
        assert_eq!(map_claims_to_role(&["waf-admins".into()], &map).or(None), Some(Role::Admin));
        // No match, no default → None (deny).
        assert_eq!(map_claims_to_role(&["other".into()], &map).or(None), None);
        // No match, with default → the default.
        assert_eq!(map_claims_to_role(&["other".into()], &map).or(Some(Role::Viewer)), Some(Role::Viewer));
    }
}
