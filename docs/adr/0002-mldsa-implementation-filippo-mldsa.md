# ADR-0002: ML-DSA via filippo.io/mldsa, migrating to stdlib crypto/mldsa

**Status:** Accepted
**Date:** 2026-07-11

## Context

MnemoCA must sign with and verify ML-DSA-44/65/87 (FIPS 204). Go landscape as of
July 2026:

- **Go 1.26** (current stable) contains a complete ML-DSA implementation inside
  the stdlib's FIPS 140-3 module (`crypto/internal/fips140/mldsa`) but does not
  expose it publicly. The public `crypto/mldsa` package is accepted for **Go 1.27**
  (golang/go#77626, ~Aug 2026).
- **`filippo.io/mldsa`** is the stdlib maintainer's extraction of that internal
  package: same code, same intended API, implements `crypto.Signer`, supports
  seed-based keys, deterministic signing, context strings, and pre-hashed μ. Its
  README states it will become a wrapper around the final stdlib API.
- **`github.com/cloudflare/circl`** (`sign/mldsa/mldsa{44,65,87}`) is mature and
  widely used, but its API diverges from the upcoming stdlib (`scheme`-based),
  adding a permanent adapter layer and a larger dependency.
- FIPS 203 (ML-KEM) needs no decision: `crypto/mlkem` and hybrid
  `X25519MLKEM768` TLS key exchange are already in the stdlib and on by default,
  covering PQ transport security for MnemoCA's own endpoints.

## Decision

1. Use **`filippo.io/mldsa`** for all ML-DSA operations, referenced from exactly
   one file (`internal/pkix/algs.go`); the rest of the codebase sees only
   `crypto.Signer`/`crypto.PublicKey` and MnemoCA's algorithm registry.
2. Set `go 1.26` in `go.mod`. When Go 1.27 ships `crypto/mldsa`, swap the import
   in that one file and bump `go.mod` — no other changes expected.
3. Store CA private keys as **32-byte seeds** (FIPS 204 §3.6.3 seed form) rather
   than expanded keys, matching RFC 9881's preference and keeping key files small
   and backend-portable.
4. Never implement cryptographic primitives in this repo. Only stdlib,
   `golang.org/x/crypto`, and `filippo.io/mldsa` (temporary) are permitted crypto
   dependencies.
5. For regulated deployments, document FIPS 140-3 mode (`GOFIPS140` module
   selection, `GODEBUG=fips140=on`) — the stdlib FIPS module covers our classical
   algorithms today and ML-DSA once we're on the stdlib package.

## Consequences

- (+) Effectively the stdlib implementation ahead of schedule; trivial migration.
- (+) FIPS 203/204 alignment with a documented path to running inside the
  validated Go FIPS 140-3 module.
- (−) Pre-v1 dependency (`v0.0.0-2026…`) until Go 1.27; pinned by go.sum, watched
  for the stdlib release. Accepted because the alternative (CIRCL) means a
  permanent non-stdlib API.
