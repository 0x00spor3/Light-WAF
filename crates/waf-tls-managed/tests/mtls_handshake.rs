// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! mTLS proof on a real (in-memory) TLS handshake, through the core's
//! `build_server_config` — i.e. exercising the `client_verifier()` seam end to end.
//!
//! Assertion: with the verifier wired, a client presenting NO certificate is REJECTED
//! by the server; with the verifier absent (control), the SAME client is ACCEPTED — so
//! the rejection is caused by the injected mTLS verifier, not by anything else.
//!
//! The client uses a no-op SERVER-cert verifier on purpose: server identity verification
//! is irrelevant noise here; the variable under test is CLIENT authentication.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{ring, CryptoProvider};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use waf_proxy::tls::{build_server_config, FileCertSource};
use waf_tls_managed::{verifier_from_ca_file, ManagedTlsCertSource};

fn tmp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("waf-mtls-{tag}-{nanos}-{}", N.fetch_add(1, Ordering::Relaxed)))
}

/// Accept any server cert — we are testing CLIENT auth, not server identity.
#[derive(Debug)]
struct NoServerVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message, cert, dss, &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message, cert, dss, &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Run one in-memory handshake. Returns whether the SERVER side completed.
async fn server_accepts(server_cfg: ServerConfig, client_cfg: ClientConfig) -> bool {
    let (cio, sio) = tokio::io::duplex(16 * 1024);
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let name = ServerName::try_from("localhost").unwrap();

    let server = tokio::spawn(async move {
        acceptor.accept(sio).await.map(|_| ()).map_err(|e| e.to_string())
    });
    let client = tokio::spawn(async move {
        match connector.connect(name, cio).await {
            // Hold the stream open briefly so the server can flush its post-handshake
            // flight (TLS 1.3 NewSessionTicket) before we drop it — otherwise an
            // ACCEPTED control handshake spuriously surfaces as "broken pipe" server-side.
            Ok(mut s) => {
                use tokio::io::AsyncWriteExt;
                let _ = s.flush().await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    });
    let (s, _c) = tokio::join!(server, client);
    s.unwrap().is_ok()
}

fn cert_less_client() -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoServerVerify(provider)))
        .with_no_client_auth()
}

#[tokio::test]
async fn mtls_rejects_client_without_cert_but_control_accepts() {
    // Server leaf (SAN localhost) → PEM files for FileCertSource.
    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = tmp("srv-cert.pem");
    let key_path = tmp("srv-key.pem");
    std::fs::write(&cert_path, server.cert.pem()).unwrap();
    std::fs::write(&key_path, server.key_pair.serialize_pem()).unwrap();

    // A CA used only as an mTLS trust root (never presented — the client sends no cert).
    let ca = rcgen::generate_simple_self_signed(vec!["client-ca".to_string()]).unwrap();
    let ca_path = tmp("ca.pem");
    std::fs::write(&ca_path, ca.cert.pem()).unwrap();

    let alpn = ["http/1.1".to_string()];

    // (1) mTLS wired → server must REJECT the cert-less client.
    let mtls = ManagedTlsCertSource::builder()
        .client_verifier(verifier_from_ca_file(&ca_path).unwrap())
        .file_fallback(FileCertSource::new(&cert_path, &key_path))
        .build();
    let mtls_cfg = build_server_config(&mtls, &alpn).unwrap();
    assert!(
        !server_accepts(mtls_cfg, cert_less_client()).await,
        "mTLS server must REJECT a client with no certificate"
    );

    // (2) Control: same everything, no verifier → server ACCEPTS the same client.
    let plain = ManagedTlsCertSource::builder()
        .file_fallback(FileCertSource::new(&cert_path, &key_path))
        .build();
    let plain_cfg = build_server_config(&plain, &alpn).unwrap();
    assert!(
        server_accepts(plain_cfg, cert_less_client()).await,
        "without the verifier the same cert-less client must be ACCEPTED (proves the verifier caused the rejection)"
    );

    for p in [cert_path, key_path, ca_path] {
        std::fs::remove_file(p).ok();
    }
}
