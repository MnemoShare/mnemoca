# ADR-0008: Audit log — append-only hash chain, signed with ML-DSA

**Status:** Accepted
**Date:** 2026-07-11

## Context

Requirement: "everything signed, who requested it, when." Regulated customers
(HITRUST, HIPAA) need tamper-evident evidence of every issuance. MnemoShare
already has SIEM export conventions in the app; MnemoCA should be consistent
but self-contained (it must stand alone as an open-source product).

## Decision

`internal/audit`:

- **Record:** canonical JSON
  `{seq, time, tenant, actor{type,id,ip}, action, object{type,id}, detail, prev_hash, hash, sig, key_id}`.
  Actions cover: CA/key lifecycle (`ca.init`, `key.generate`, `key.destroy`),
  issuance (`cert.issue`, `cert.renew`, `cert.revoke`, `crl.publish`), ACME
  (`acme.account.new`, `acme.order.finalize`, …), admin (`tenant.create`,
  `apikey.create`, …), and `audit.checkpoint`.
- **Chain:** `hash = SHA-256(prev_hash ‖ canonical(record-without-hash-sig))`;
  genesis uses a random anchor recorded at `ca.init`.
- **Signature:** every record signed by a dedicated **audit key** (ML-DSA-65 via
  the signer backend — the audit trail itself is quantum-resistant; an audit key
  in an HSM signs audit records with the same `Backend` interface as issuance).
- **Storage:** append-only JSONL segment files, fsync'd per batch, plus the
  chain head in the store for fast integrity checks. `mnemoca audit verify`
  replays segments and validates chain + signatures offline given only the
  audit public key.
- **Checkpoints:** periodic signed checkpoint records (seq + head hash) make
  truncation detectable, not just modification.
- **Export:** tail-to-syslog/webhook shipper matching MnemoShare SIEM export
  format (Phase 4 wiring).
- Issuance is **audit-gated**: the certificate is not released to the caller
  until its `cert.issue` record is durably appended (write-ahead auditing).

## Consequences

- (+) Offline-verifiable, tamper-evident, PQ-safe evidence chain; maps directly
  onto HITRUST logging controls.
- (+) Same signer plumbing as issuance — no second key-handling code path.
- (−) Write-ahead auditing puts an fsync in the issuance path; acceptable at
  MnemoCA issuance rates (machine identity, not Let's Encrypt scale) and
  batched under load.
- (−) Log deletion by a root-level attacker is only *detectable* (checkpoints,
  SIEM export), not preventable — stated explicitly in the threat model docs.
