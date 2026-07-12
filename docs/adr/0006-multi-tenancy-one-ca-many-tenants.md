# ADR-0006: Multi-tenancy — one CA instance, per-tenant issuing CAs

**Status:** Accepted
**Date:** 2026-07-11

## Context

Today one shared Step-CA instance (`app/k8s/step-ca/`) serves 30–40+ SaaS
customers with a single JWK provisioner; tenant isolation is only CN/SAN
convention inside one issuance domain, and one global CRL. MnemoCA must keep
the operational win (one deployment) while fixing the isolation model, and also
serve single-tenant self-hosted installs without extra concepts.

## Decision

- A MnemoCA instance hosts one **root domain** (a root CA, or a classical+ML-DSA
  root *pair* per ADR-0004) and N **tenants**.
- Each tenant gets its **own issuing CA** (own key via any signer backend, own
  profiles, own serial space, own CRL) chained to the shared root. A
  self-hosted install is simply the built-in `default` tenant.
- **Regulated option:** a tenant may instead be anchored to its own external or
  dedicated root ("bring your own root"), for customers who cannot share a trust
  anchor. Same tenant API, different chain.
- Scoping is structural, not conventional:
  - API: every key/cert/profile object lives under `/api/v1/tenants/{tenant}/…`;
    API keys are tenant-bound (plus a separate operator role for tenant CRUD).
  - ACME: per-tenant directory `/acme/{tenant}/directory`; External Account
    Binding required in SaaS mode so only provisioned tenants can register.
  - Storage: bbolt buckets (or DB collections) keyed by tenant ID.
  - Audit: tenant ID on every record; per-tenant export filters.
- SaaS lifecycle: `mnemo-provisioner` calls tenant create/destroy as one of its
  provision tasks, replacing the Step-CA step; the MnemoShare app consumes the
  tenant's issuing CA through the `ca.Provider` implementation (PLAN §Phase 4).

## Consequences

- (+) Revoking or rotating one tenant's issuing CA cannot affect another tenant;
  per-tenant CRLs stay small; blast radius of a tenant-scoped credential is one
  tenant.
- (+) Strictly better than the Step-CA model it replaces, with the same
  single-deployment operations story.
- (−) One issuing key per tenant (more keys to manage than one shared
  provisioner) — this is the point; softkey backend makes it cheap, and key
  material is enumerable via the API for rotation tooling.
- (−) Shared root remains a shared trust anchor across SaaS tenants; documented,
  with BYO-root as the escape hatch.
