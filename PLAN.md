# MnemoCA — MnemoShare Certificate Authority

**Status:** Planning → Implementation (v0)
**License:** Apache-2.0 (open source)
**Repository:** `mnemoshare/mnemoshare-ca` (monorepo path: `mnemoshare-ca/`)

## 1. Why we are building this

MnemoShare today supports Step-CA and HashiCorp Vault as certificate backends for
hardware mTLS. Neither has a credible, shippable post-quantum story we control:

- **EJBCA** was suggested for PQC readiness. Rejected: it is a heavyweight Java
  product owned by a third party (Keyfactor). Asking self-hosted, regulated
  customers to operate a third-party CA we do not control contradicts the
  MnemoShare model (single image, Kubernetes-native, identity-bound, minimal
  operational surface).
- **Step-CA** has no ML-DSA issuance today and its PQC roadmap is not ours to set.
- CNSA 2.0 and sector regulators are already signaling ML-DSA timelines;
  "harvest now, decrypt later" makes signature migration for long-lived device
  identities (YubiKey, TPM, Secure Enclave enrollments) a now-problem.

**Decision: build MnemoCA** — a small, opinionated, open-source CA in Go, purpose-built
for PQC-era machine identity, usable standalone by anyone and natively by MnemoShare
for both self-hosted deployments and SaaS (one CA, many cert tenants — the Step-CA
role it replaces).

## 2. Minimum requirements (v1 scope)

1. **Basic ACME support (RFC 8555)** — enough that cert-manager in Kubernetes talks
   to it with zero custom code: directory, newNonce, newAccount, newOrder,
   authorizations, `http-01` and `dns-01` challenges, finalize, certificate download,
   External Account Binding (EAB) for tenant scoping.
2. **Hybrid and pure ML-DSA certificate issuance**
   - Pure ML-DSA-44/65/87 certificates and CRLs per **RFC 9881** (X.509 algorithm
     identifiers for ML-DSA; NIST OIDs `2.16.840.1.101.3.4.3.{17,18,19}`).
   - Composite ML-DSA certificates per **draft-ietf-lamps-pq-composite-sigs**
     (pinned to draft-19; explicitly marked experimental until RFC).
   - Classical issuance (ECDSA P-256/P-384, Ed25519, RSA verify-only) so MnemoCA
     can replace Step-CA for existing hardware mTLS flows on day one.
   - "Hybrid" also includes the operationally boring path: parallel classical +
     pure-PQ chains (dual issuance from paired roots), which works with today's
     TLS stacks while composite drafts settle.
3. **Simple pluggable signing backend** — a small Go interface (`crypto.Signer`-shaped)
   with built-in backends: software keys (encrypted on disk), and clean plug points
   for PKCS#11 HSMs and cloud KMS. Third parties implement one interface.
4. **Good audit logging** — every security-relevant event (key generation, issuance,
   revocation, ACME account changes, admin actions) recorded in an append-only,
   hash-chained log, each entry signed by the CA audit key; who, what, when,
   from where, under which tenant.
5. **Basic CLI and API**
   - `mnemoca` — the open-source CLI shipped with this repo (init, serve, issue,
     revoke, inspect, token, tenant, audit verify).
   - JSON REST API for everything the CLI does.
   - `mnemocli ca …` subcommands added to MnemoShare's existing CLI (`../app`)
     for integrated deployments (separate work item in the app repo).
6. **Multi-tenancy** — one MnemoCA instance serves many tenants (SaaS model):
   per-tenant issuing CAs chained to a shared root (default) or fully separate
   per-tenant roots (regulated option). Tenant isolation enforced at API, ACME
   (EAB), storage, and audit layers.

### Non-goals for v1
- OCSP responder (CRL + short-lived certs first; OCSP later if demanded).
- Full RFC 8555 completeness (`tls-alpn-01`, pre-authorization, account key
  rollover can follow in v1.x).
- SCEP/EST/CMP legacy enrollment protocols.
- A web UI (API + CLI only; MnemoShare's app UI integrates via API).
- SLH-DSA (FIPS 205) issuance — the algorithm registry is designed so it can be
  added, but stateless hash signatures are large and slow; wait for demand.

## 3. Cryptography & standards baseline

| Concern | Choice | Standard |
|---|---|---|
| PQ signatures | ML-DSA-44/65/87 | FIPS 204 |
| PQ KEM (transport) | ML-KEM-768 via Go TLS hybrid `X25519MLKEM768` | FIPS 203, RFC 9935 |
| ML-DSA in X.509 | NIST OIDs, seed/expanded key encodings | RFC 9881 |
| Composite certs | COMPSIG ML-DSA + ECDSA/Ed25519/RSA | draft-ietf-lamps-pq-composite-sigs-19 (experimental) |
| Enrollment | ACME | RFC 8555 |
| Classical sigs | ECDSA P-256/P-384, Ed25519 | FIPS 186-5 |

**Go version strategy.** `go 1.26` in `go.mod` (current stable). FIPS 203 (ML-KEM)
ships in the stdlib (`crypto/mlkem`, TLS `X25519MLKEM768` on by default). ML-DSA is
implemented inside the stdlib's FIPS 140-3 module in Go 1.26 but the public
`crypto/mldsa` package lands in Go 1.27 (Aug 2026). Until then we use
**`filippo.io/mldsa`** — the maintainer's frozen preview of the exact stdlib API,
extracted from `crypto/internal/fips140/mldsa`, implementing `crypto.Signer`. When
Go 1.27 ships, the swap is a one-file change in `internal/pkix/algs.go` (the package
is designed to become a wrapper around the stdlib). FIPS 140-3 mode is a build/run
flag (`GOFIPS140=v1.0.0` / `GODEBUG=fips140=on`), which we document for regulated
deployments.

**X.509 construction.** Go's `crypto/x509` cannot sign or parse ML-DSA/composite
certificates yet, so MnemoCA carries its own minimal DER layer
(`golang.org/x/crypto/cryptobyte`) for TBSCertificate/CSR/CRL assembly, delegating
to `crypto/x509` for everything classical. This is ~1,500 lines we fully control,
not a fork of the stdlib. See ADR-0003.

## 4. Architecture

```
mnemoshare-ca/
├── cmd/
│   ├── mnemoca/            # Open-source CLI (init, serve, issue, revoke, inspect, tenant, audit)
│   └── mnemoca-server/     # (alias of `mnemoca serve`; single multi-call binary like app/)
├── internal/
│   ├── pkix/               # Algorithm registry, ML-DSA & composite X.509 DER (RFC 9881, composite-19)
│   ├── ca/                 # CA engine: profiles, chains, issue/renew/revoke, CRL
│   ├── signer/             # Pluggable signing backends: softkey, pkcs11 (stub), kms (stub)
│   ├── tenant/             # Tenant model, per-tenant issuing CAs, quotas
│   ├── acme/               # RFC 8555 server subset + EAB
│   ├── api/                # REST API (chi or stdlib mux), authn (API keys / mTLS)
│   ├── audit/              # Hash-chained signed audit log
│   └── store/              # Storage: bbolt (default, single-file) + MongoDB via goodm (HA, ADR-0010)
├── pkg/
│   └── mnemoca/            # Public Go client library (used by app/ and third parties)
├── docs/adr/               # Architecture Decision Records
├── PLAN.md
└── README.md
```

Runtime shape mirrors the rest of MnemoShare: one Go binary, one Docker image,
Helm-chart deployable, state in a mounted volume (bbolt) or external DB.

### Multi-tenant model (one CA, many cert tenants)

```
                 MnemoCA Root (offline-capable, ML-DSA-87 or ECDSA P-384 — or both, paired)
                        │
        ┌───────────────┼────────────────────┐
   Tenant A issuing CA  Tenant B issuing CA  Platform issuing CA
   (ML-DSA-65)          (composite)           (MnemoShare internal mTLS)
        │                    │
   leaf certs           leaf certs
```

- Each tenant gets an **issuing CA** (its own key, its own profile defaults).
- ACME: one directory URL per tenant (`/acme/{tenant}/directory`) plus EAB keys,
  so cert-manager `Issuer` objects are tenant-scoped with stock configuration.
- API keys and audit records carry tenant IDs; storage is keyed by tenant.
- SaaS provisioner integration: provisioning a MnemoShare tenant calls
  `POST /api/v1/tenants` — replacing today's Step-CA provisioner step.

### Signing backend interface

```go
// Signer is the single interface a backend must implement.
type Signer interface {
    Public() crypto.PublicKey
    Sign(rand io.Reader, digestOrMessage []byte, opts crypto.SignerOpts) ([]byte, error)
    // Algorithm reports the registered algorithm (e.g. MLDSA65, ECDSAP256, composite IDs).
    Algorithm() pkix.Algorithm
}

// Backend creates and opens keys. Implementations: softkey, pkcs11, kms.
type Backend interface {
    Generate(ctx context.Context, alg pkix.Algorithm, label string) (Signer, error)
    Open(ctx context.Context, ref KeyRef) (Signer, error)
    Destroy(ctx context.Context, ref KeyRef) error
}
```

Note: ML-DSA signs *messages*, not digests (no pre-hash in the default profile),
so the interface passes the full message through; classical backends digest
internally. HSM/KMS ML-DSA support is emerging — softkey is the reference
backend, and the interface is what vendors implement.

### Audit log

Append-only JSONL; each record `{seq, time, tenant, actor, action, object, detail,
prev_hash, hash, sig}` where `hash = SHA-256(prev_hash || canonical_record)` and
`sig` is an ML-DSA-65 signature by a dedicated audit key. `mnemoca audit verify`
replays the chain. Export hooks (syslog/webhook) reuse MnemoShare SIEM conventions.

## 5. Phased roadmap

| Phase | Deliverable | Definition of done |
|---|---|---|
| **0 — Foundations** (this repo, now) | Plan + ADRs + `internal/pkix`: algorithm registry, ML-DSA cert/CSR/CRL DER, composite signing | Round-trip tests: issue & verify pure ML-DSA and composite certs; classical parity |
| **1 — CA core** | `internal/ca`, `signer/softkey`, `store/bbolt`, `tenant` | `mnemoca init` creates root+issuing CA; `mnemoca issue` signs a CSR; revoke + CRL |
| **2 — API + audit + CLI** | REST API, hash-chained audit, full `mnemoca` CLI | Everything scriptable; audit chain verifies |
| **3 — ACME** | RFC 8555 subset + EAB | cert-manager (ACME issuer) obtains a cert end-to-end against MnemoCA in kind |
| **4 — MnemoShare integration** | `mnemocli ca` subcommands in `../app`; hardware-mTLS backend option `mnemoca` alongside step-ca/vault; provisioner tenant step | Dev namespace runs MnemoCA-issued mTLS |
| **5 — Hardening / OSS release** | pkcs11/kms backends, FIPS mode docs, Helm chart, fuzzing DER parsers, security review | Public repo, Artifact Hub chart, tagged v0.1.0 |
| **HA storage** (ADR-0010) — ✅ done | `store.Store` interface; MongoDB backend via goodm; store-backed keys (`storekey`) and audit chain; `--db bolt\|mongo` | ✅ Conformance suite passes on both backends; end-to-end (init → issue → revoke → CRL → audit verify) runs against MongoDB; replicas stateless in mongo mode |

Phases 0–3 live entirely in this repo and are what "(c) implement the code" covers
first. Phase 4 touches `app/` and `mnemo-provisioner/` and lands as separate PRs.

### Phase 4 integration map (existing code)

- `app/internal/ca/provider.go` already defines the backend abstraction
  (`Provider`: `SignCSR`, `RenewCertificate`, `CheckRevocation`,
  `GetCACertificate`, `RevokeCertificate`, `ListCertificates`) with
  `smallstep.go` and `vault.go` implementations. MnemoCA integration is a third
  implementation, `mnemoca.go`, backed by `pkg/mnemoca` (this repo's client
  library) — MnemoCA's REST API is designed to map 1:1 onto that interface.
- `app/cmd/mnemocli/cmd/` is cobra-based; `ca.go` adds `mnemocli ca
  {status,issue,revoke,certs,tenants}` following the `hardware.go` pattern.
- `app/k8s/step-ca/` (shared Step-CA for 30–40 SaaS customers, JWK provisioner,
  global CRL) is the deployment MnemoCA replaces; the tenant model above is a
  strict upgrade (per-tenant issuing CAs instead of CN/SAN-based isolation
  under one provisioner).

## 6. Risks

- **Composite draft churn.** draft-19 OIDs may change before RFC. Mitigation:
  version-tag composite profiles (`composite-draft-19`), gate behind an
  `--experimental-composite` flag, keep pure ML-DSA + parallel-chain hybrid as the
  supported paths.
- **Ecosystem verification gaps.** Browsers/proxies don't verify ML-DSA chains yet.
  Mitigation: MnemoCA is aimed at machine identity (mTLS inside meshes and between
  MnemoShare components) where we control both ends; dual-chain issuance covers
  mixed estates.
- **`crypto/mldsa` API drift in Go 1.27.** Mitigation: filippo.io/mldsa is the
  declared preview of that API; usage confined to one file.
- **HSM ML-DSA availability.** Mitigation: softkey backend first; interface designed
  from PKCS#11 3.2 ML-DSA mechanisms so hardware slots in without core changes.
