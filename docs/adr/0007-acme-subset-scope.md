# ADR-0007: ACME scope — the cert-manager-sufficient subset of RFC 8555

**Status:** Accepted
**Date:** 2026-07-11

## Context

The requirement is that cert-manager in Kubernetes can obtain certificates from
MnemoCA with stock configuration (`ACME` issuer type, no custom webhook code).
Full RFC 8555 plus every extension is a large surface; cert-manager exercises a
well-defined subset.

## Decision

Implement in `internal/acme`, v1 scope:

- **Endpoints:** directory, newNonce, newAccount, newOrder, authorization,
  challenge, finalize, order status, certificate download, revokeCert.
  One directory per tenant: `/acme/{tenant}/directory` (ADR-0006).
- **Challenges:** `http-01` and `dns-01`. (`tls-alpn-01` deferred.)
- **Account keys:** ES256 and RS256 JWS (what cert-manager sends). EdDSA
  accepted. ML-DSA JWS deferred until JOSE algorithm registration settles —
  the *certificates* issued are PQC regardless of account-key algorithm.
- **External Account Binding:** required in SaaS mode, optional self-hosted;
  EAB HMAC keys minted per tenant via the admin API.
- **Finalize:** the CSR's requested algorithm must be permitted by the tenant's
  profile; the profile (not the client) decides the *signing* algorithm of the
  issued cert, so a stock cert-manager with an ECDSA key can still receive a
  cert signed by an ML-DSA issuing CA. Pure ML-DSA *leaf keys* via ACME arrive
  when client tooling can generate such CSRs (cert-manager tracking issue noted
  in docs); MnemoCA's own CSR path supports them today.
- **Deferred:** pre-authorization, account key rollover, orders list, deactivate
  →

  These return `urn:ietf:params:acme:error:malformed`/`unsupported` properly
  rather than 404s, so clients degrade cleanly.

Nonces are single-use, stored server-side with TTL; all object URLs are
capability URLs bound to the account; JWS verification enforces `kid`/`jwk`
rules per RFC 8555 §6.2.

## Consequences

- (+) cert-manager works with a stock `Issuer`; scope is testable end-to-end in
  kind (Phase 3 exit criterion).
- (+) Small enough surface to audit; ACME code never touches signing keys — it
  calls the same `internal/ca` issuance path as the REST API, so audit and
  profile enforcement are uniform.
- (−) Not a general-purpose public ACME service (no tls-alpn-01, no key
  rollover) until v1.x; documented in the compatibility matrix.
