# ADR-0001: Build MnemoCA instead of adopting EJBCA

**Status:** Accepted
**Date:** 2026-07-11

## Context

MnemoShare's hardware mTLS feature issues client certificates through a pluggable
CA backend (`app/internal/ca/provider.go`), currently implemented for Step-CA and
HashiCorp Vault. For post-quantum readiness (ML-DSA issuance), EJBCA was suggested,
since it already ships PQC issuance support.

Constraints that matter to MnemoShare:

- **Self-hosted customers.** MnemoShare sells to regulated industries that deploy
  the whole platform themselves. Every third-party dependency in the critical path
  is a component the customer must license, operate, patch, and trust — and one
  we cannot fix when it breaks.
- **Operational model.** MnemoShare ships as a single multi-binary Go image,
  Kubernetes-native, with small resource footprints per SaaS tenant. EJBCA is a
  large Java EE application (application server, SQL database, its own upgrade
  cadence) owned by Keyfactor, with the full feature set behind an enterprise
  edition.
- **SaaS model.** One shared CA serves 30–40+ tenants today (`app/k8s/step-ca/`).
  Whatever replaces Step-CA must support one-CA/many-tenants natively.
- **Roadmap control.** PQC standards are still moving (composite certs are at
  draft-19). We need to track drafts on our schedule, not a vendor's.

## Decision

Build **MnemoCA**, a purpose-built, open-source (Apache-2.0) certificate authority
in Go, with a deliberately minimal scope: ACME for Kubernetes, pure and hybrid
ML-DSA issuance, pluggable signing backends, signed audit logging, CLI + REST API,
and first-class multi-tenancy. Do not adopt EJBCA; do not extend Step-CA.

## Consequences

- (+) Full control of PQC timeline, tenancy model, and deployment shape; same
  language, tooling, and CI as the rest of the platform.
- (+) Self-hosted customers get a CA that is part of the product, not a
  third-party install; open source means they can audit it.
- (+) The `ca.Provider` abstraction in `app/` means MnemoCA is additive — Step-CA
  and Vault support remain during migration.
- (−) We own security-critical code: X.509 construction, ACME, key handling.
  Mitigated by keeping scope minimal, reusing stdlib/curated crypto (never
  implementing primitives ourselves — see ADR-0002), fuzzing DER parsers, and an
  external security review before v1 (Phase 5).
- (−) No OCSP, SCEP/EST/CMP, or web UI at launch — acceptable; not required by
  any current MnemoShare flow.
