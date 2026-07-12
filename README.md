# MnemoCA

**An open-source, post-quantum-ready certificate authority in Go.**

MnemoCA is a small, opinionated CA built for the ML-DSA era of machine
identity: pure and hybrid post-quantum certificate issuance, ACME for
Kubernetes, pluggable signing backends, a tamper-evident signed audit log,
and first-class multi-tenancy — one CA instance, many certificate tenants.

Built by [MnemoShare](https://mnemoshare.com) as the certificate backbone of
its secure MFT platform, and released under Apache-2.0 for anyone who needs a
PQC-capable CA they can actually read.

## Why

NIST finalized the post-quantum signature standard **ML-DSA (FIPS 204)** in
2024 and its X.509 profile (**RFC 9881**) in 2025. Long-lived machine
identities — hardware-bound mTLS client certificates, service mesh identities,
device enrollments — need quantum-resistant signatures *now*, not when the
incumbent CA stacks get around to it. MnemoCA is deliberately minimal:
~an afternoon to read the issuance path end to end.

## Features

- **Pure ML-DSA issuance** — ML-DSA-44/65/87 certificates, CSRs, and CRLs per
  RFC 9881 (FIPS 204).
- **Hybrid issuance** — parallel classical + ML-DSA chains from a paired root
  (works with every deployed TLS stack), plus experimental composite
  certificates per draft-ietf-lamps-pq-composite-sigs-19 behind
  `--experimental-composite`.
- **Classical issuance** — ECDSA P-256/P-384 and Ed25519, byte-identical to
  Go's crypto/x509.
- **ACME (RFC 8555)** — the subset cert-manager needs: http-01, dns-01,
  External Account Binding; per-tenant directories.
- **Multi-tenant** — every tenant gets its own issuing CA, serial space, and
  CRL under a shared (or dedicated) root.
- **Pluggable signing** — one small `Backend` interface; encrypted software
  keys built in, PKCS#11/KMS plug points defined.
- **Signed audit log** — append-only hash chain, every record signed with a
  dedicated ML-DSA-65 key, offline-verifiable with just the public key.
- **CLI + REST API** — everything scriptable; JSON API for integration.

## Quick start

```bash
go install github.com/mnemoshare/mnemoca/cmd/mnemoca@latest

export MNEMOCA_PASSPHRASE=change-me

# Hybrid root: ML-DSA-87 primary + ECDSA P-384 pair
mnemoca init --alg ml-dsa-87 --pair-alg ecdsa-p384 --name "My Root"

# A tenant with its own issuing CA on both chains
mnemoca tenant create prod --hybrid

# Issue: generate an ML-DSA-65 key, CSR, and certificate
mnemoca keygen --alg ml-dsa-65 -o svc.key
mnemoca csr --key svc.key --cn svc.internal --dns svc.internal -o svc.csr
mnemoca issue --tenant prod --csr svc.csr -o svc.pem

mnemoca inspect svc.pem
mnemoca audit verify

# Serve the REST API + ACME
mnemoca serve --listen :8443 --external-url https://ca.example.com
```

### cert-manager

Point a stock ACME `Issuer` at a tenant directory:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: mnemoca
spec:
  acme:
    server: https://ca.example.com/acme/prod/directory
    externalAccountBinding:
      keyID: <eab-kid>
      keySecretRef: {name: mnemoca-eab, key: secret}
    privateKeySecretRef:
      name: mnemoca-account
    solvers:
      - http01: {ingress: {class: nginx}}
```

## Algorithms

| Algorithm | ID | Status |
|---|---|---|
| ECDSA P-256 / P-384 | `ecdsa-p256`, `ecdsa-p384` | stable |
| Ed25519 | `ed25519` | stable |
| ML-DSA-44/65/87 (FIPS 204, RFC 9881) | `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` | stable |
| Composite ML-DSA-65 + ECDSA P-256 | `composite-draft-19-mldsa65-ecdsa-p256-sha256` | experimental (draft-19) |
| Composite ML-DSA-44 + Ed25519 | `composite-draft-19-mldsa44-ed25519-sha512` | experimental (draft-19) |

ML-KEM (FIPS 203) protects MnemoCA's own TLS endpoints via Go's default
`X25519MLKEM768` hybrid key exchange.

Composite profiles track the IETF LAMPS draft and are version-stamped; they
will change when the RFC publishes. Parallel-chain hybrid (`--pair-alg` +
`--chain both`) is the supported hybrid mode.

## Design

Start with [PLAN.md](PLAN.md) and the ADRs in [docs/adr/](docs/adr/):
why we built this instead of adopting EJBCA (ADR-0001), the ML-DSA
implementation strategy (ADR-0002), the minimal X.509 DER layer (ADR-0003),
hybrid strategy (ADR-0004), signer backends (ADR-0005), multi-tenancy
(ADR-0006), ACME scope (ADR-0007), the audit chain (ADR-0008), and licensing
(ADR-0009).

```
cmd/mnemoca        CLI (init, serve, tenant, issue, revoke, inspect, audit)
internal/pkix      algorithm registry + ML-DSA/composite X.509 DER layer
internal/ca        CA engine: roots, tenants, profiles, issuance, CRLs
internal/signer    pluggable signing backends (softkey; pkcs11/kms stubs)
internal/acme      RFC 8555 server subset + EAB
internal/api       REST API
internal/audit     hash-chained, ML-DSA-signed audit log
internal/store     embedded bbolt store
```

## Status

v0 — under active development. The issuance core (pure ML-DSA, composite,
classical, CSRs, CRLs, audit chain) is implemented and tested; ACME and the
REST API are stabilizing. Not yet audited — do not put a production root on
it without reading ADR-0005 and putting keys in your own backend.

## License

Apache-2.0. See [LICENSE](LICENSE).
