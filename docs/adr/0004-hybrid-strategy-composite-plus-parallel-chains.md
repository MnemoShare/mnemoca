# ADR-0004: Hybrid strategy — parallel chains supported, composite experimental

**Status:** Accepted
**Date:** 2026-07-11

## Context

"Hybrid ML-DSA issuance" has two common meanings:

1. **Composite certificates** — one certificate whose key and signature are a
   composite of ML-DSA + a classical algorithm
   (draft-ietf-lamps-pq-composite-sigs, currently **draft-19**; OID arc
   `1.3.6.1.5.5.7.6.x`). Single artifact, atomic dual security — but the draft
   is not an RFC, OIDs and encodings have already changed across draft revisions,
   and TLS stacks do not verify them.
2. **Parallel chains (dual issuance)** — issue each subject two certificates, one
   classical chain and one pure ML-DSA chain, from paired roots. Boring, works
   with every deployed TLS stack today, and lets relying parties migrate
   independently.

MnemoCA's primary consumers are machine identities where we often control both
endpoints (MnemoShare mTLS), but ACME clients like cert-manager expect standard
certificates.

## Decision

- **Pure ML-DSA (RFC 9881) and classical issuance are the two supported
  first-class paths.**
- **Parallel-chain hybrid is the supported hybrid mode:** a CA can be initialized
  as a *pair* (classical root + ML-DSA root); issuance profiles may request
  `hybrid: parallel`, returning two certificates for one subject/key-pair set.
- **Composite issuance ships behind `--experimental-composite`,** implemented
  against draft-19 exactly, with the draft version stamped into the profile name
  (`composite-draft-19`) and into audit records. Initial composite set:
  `MLDSA65-ECDSA-P256-SHA256` and `MLDSA44-Ed25519-SHA512`, extended on demand.
  When the RFC publishes, final OIDs become the stable profile and draft profiles
  are retired on a documented deprecation schedule.

## Consequences

- (+) Customers get PQC protection today without betting on a moving draft;
  composite adopters are clearly opted in.
- (+) Draft churn is contained to one registry section in `internal/pkix`.
- (−) Parallel chains double certificate count and require relying-party logic to
  pick a chain; acceptable for machine identity, and documented.
- (−) Composite profiles may need breaking changes before RFC; the experimental
  flag and versioned profile names make that contract explicit.
