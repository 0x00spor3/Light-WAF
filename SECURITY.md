# Security Policy

Light WAF is a security product, so we treat vulnerabilities in it — including ways to get an
attack past it — as security issues, not ordinary bugs.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/0x00spor3/Light-WAF/security/advisories/new)**
(repository → *Security* tab → *Report a vulnerability*).

Please include:

- the affected component (crate, binary, chart) and version or commit;
- the configuration needed to reproduce it (paranoia level, mode, enabled modules);
- a minimal reproduction — for a detection bypass, the exact request (e.g. a `curl` command)
  and the verdict you got versus the one you expected;
- the impact as you understand it.

## What to expect

- **Acknowledgement** within 7 days.
- An initial **assessment** (accepted / not a vulnerability / needs more information) within
  14 days.
- For accepted reports, we develop the fix in a private advisory, agree on a disclosure date
  with you, and publish the advisory together with the fixed release. Reporters are credited in
  the advisory unless they prefer otherwise.

This is a community-maintained project; the timelines above are targets, not a contractual SLA.

## Scope

In scope — please report privately:

- **Detection bypasses**: a request that carries a working attack in a category the WAF claims to
  cover, yet is allowed at a paranoia level where it should be blocked (evasion through encoding,
  normalization or parsing differences between the WAF and common backends).
- Vulnerabilities in the **proxy** itself: memory-safety issues, crashes or panics reachable from
  a request, request smuggling / desync through the proxy, resource exhaustion that a single
  client can trigger, TLS issues.
- Vulnerabilities in the **control plane, node agent and operator**: authentication or
  authorization bypass, RBAC escalation, session or token flaws, audit-log tampering that verifies
  as valid, injection, SSRF, exposure of secrets or captured request data.
- Supply-chain issues in what this repository builds: signature-verification bypass for WASM
  plugins, insecure defaults in the container images or Helm charts.

Out of scope:

- False positives (legitimate traffic blocked) — please open a normal issue.
- Attacks in categories the WAF does not claim to cover, or bypasses only at a paranoia level
  documented as not covering that case.
- Findings that require an already-compromised host, config file or Kubernetes cluster admin.
- Vulnerabilities in third-party dependencies with no demonstrated impact on Light WAF — report
  those upstream. Known CVEs in base images are tracked by the image scan in CI (`.trivyignore`
  documents every accepted exception and its expiry).

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ — the 0.x core releases are superseded by 1.0 |

Security fixes are released as patch versions of the latest minor line.

## Verifying the container images

From 1.0.2, every image on `ghcr.io/0x00spor3` (`waf-enterprise`, `waf-controlplane`,
`waf-node-agent`, `waf-operator`) is signed with [cosign](https://github.com/sigstore/cosign) when
the release workflow publishes it. The signing is keyless: there is no public key to distribute.
The signature is bound to the identity of this repository's `images.yml` workflow and recorded in
the public Sigstore transparency log. Each image also carries a signed SPDX SBOM.

Check that an image was built and signed by this repository's release workflow (cosign 2.4 or
later):

```sh
cosign verify ghcr.io/0x00spor3/waf-enterprise:1.0.2 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/0x00spor3/Light-WAF/\.github/workflows/images\.yml@refs/(tags/v.+|heads/main)$'
```

A release published by pushing its tag is signed from `refs/tags/v…`; a re-publish of an existing
tag, run by hand from `main`, is signed from `refs/heads/main`. The expression accepts both and
nothing else, so a fork or another workflow cannot produce a signature that passes.

To check the SBOM attestation and read the SBOM:

```sh
cosign verify-attestation ghcr.io/0x00spor3/waf-enterprise:1.0.2 --type spdxjson \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/0x00spor3/Light-WAF/\.github/workflows/images\.yml@refs/(tags/v.+|heads/main)$' \
  | jq -r '.payload' | base64 -d | jq '.predicate'
```

The Helm charts on `ghcr.io/0x00spor3/charts` are signed the same way by `charts-release.yml`:

```sh
cosign verify ghcr.io/0x00spor3/charts/waf:1.0.2 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/0x00spor3/Light-WAF/\.github/workflows/charts-release\.yml@refs/(tags/v.+|heads/main)$'
```

The image SBOMs list what is visible inside each image (OS packages, the CA bundle). They cannot see
the Rust crates compiled into the binaries. For the full dependency inventory, use the source SBOM
attached to the release (next section).

## Verifying the release assets

From 1.0.2, each [GitHub Release](https://github.com/0x00spor3/Light-WAF/releases) carries:

- the source tree, `light-waf-<version>-source.tar.gz`;
- the source SBOM, `light-waf-<version>-source.spdx.json`, which lists every Rust crate and npm
  package;
- the SBOM of each image;
- `SHA256SUMS`.

Each of these files comes with a `<file>.sigstore.json` keyless signature bundle, made by the
`release-assets.yml` workflow. To verify one:

```sh
cosign verify-blob light-waf-1.0.2-source.tar.gz \
  --bundle light-waf-1.0.2-source.tar.gz.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/0x00spor3/Light-WAF/\.github/workflows/release-assets\.yml@refs/(tags/v.+|heads/main)$'
```

Or verify `SHA256SUMS` the same way, then check every other file against it with
`sha256sum -c SHA256SUMS`.

## Enforcing signatures in Kubernetes

An admission policy can require the image signature before a pod starts. Examples are
the [Sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/) and
[Kyverno](https://kyverno.io/docs/writing-policies/verify-images/), configured with the same
issuer and identity.
