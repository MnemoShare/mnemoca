# ADR-0005: Pluggable signing backend interface

**Status:** Accepted
**Date:** 2026-07-11

## Context

Customers must be able to hold CA keys in their own HSM or cloud KMS, or in
software keys for dev/small deployments. ML-DSA complicates the classical
`crypto.Signer` contract: ML-DSA signs the *message* (with internal μ
computation), not a digest, and pre-hash variants (HashML-DSA) are discouraged
for certificates. PKCS#11 3.2 defines ML-DSA mechanisms; cloud KMS ML-DSA
support is emerging but uneven.

## Decision

`internal/signer` defines the plug point:

```go
type Signer interface {
    crypto.Signer                 // Public() + Sign(rand, data, opts)
    Algorithm() pkix.Algorithm    // registered algorithm identity
}

type Backend interface {
    Name() string
    Generate(ctx context.Context, alg pkix.Algorithm, label string) (Signer, KeyRef, error)
    Open(ctx context.Context, ref KeyRef) (Signer, error)
    Destroy(ctx context.Context, ref KeyRef) error
}
```

- For ML-DSA algorithms, `Sign` receives the **full to-be-signed message** with
  `opts.HashFunc() == 0` (mirroring how Ed25519 and the upcoming `crypto/mldsa`
  use `crypto.Signer`); classical algorithms receive a digest as usual. The
  `internal/pkix` builder — not backends — decides which form to pass.
- `KeyRef` is an opaque URI persisted in CA metadata:
  `softkey:<file>`, `pkcs11:token=…;label=…`, `awskms:arn…`, `gcpkms://…`.
  The scheme selects the backend at open time.
- **v0 ships `softkey`**: seed/PKCS#8 keys encrypted at rest with AES-256-GCM
  under a scrypt-derived key file password or injected secret (Kubernetes Secret),
  consistent with MnemoShare's application-layer encryption posture.
- `pkcs11` and `kms` packages ship as compile-time-included stubs implementing
  `Backend` with clear `ErrNotImplemented`, so the wiring, config surface, and
  docs exist from day one and hardware support is additive (Phase 5).

## Consequences

- (+) One small interface for third parties; backends can't get the ML-DSA
  message-vs-digest question wrong because the builder owns it.
- (+) Registry-driven: adding SLH-DSA or new composites doesn't change `Backend`.
- (−) `crypto.Signer`'s `io.Reader` rand parameter is unused by deterministic
  ML-DSA paths — minor interface noise, kept for stdlib compatibility.
