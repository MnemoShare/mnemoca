# ADR-0011: Deployment topology and trust boundary

**Status:** Accepted
**Date:** 2026-11-03

## Context

MnemoCA is the certificate authority behind MnemoShare's hardware-key mTLS
(YubiKey, Secure Enclave, TPM client certificates). It replaces the shared
Step-CA that currently issues those certificates for every SaaS tenant. A CA is
the highest-value target in the platform, so how it is deployed, who can reach
it, and how its first credential is handled are architecture, not packaging
detail. The Helm chart in `charts/mnemoca` encodes these decisions.

## Decision

### Role and trust boundary

- MnemoShare is the only intended client. The MnemoShare app (and the
  provisioner) call the REST API to issue and revoke tenant client
  certificates; relying parties trust the roots served at `/roots` and consume
  CRLs from `/crl/{tenant}`.
- One MnemoCA instance serves many MnemoShare tenants as MnemoCA tenants
  (ADR-0006): an API key is either operator (all tenants) or tenant-scoped.
  MnemoShare holds tenant-scoped keys per customer; only platform operations
  hold the operator key.
- The signing keys never leave the CA's boundary: encrypted software keys under
  a passphrase today, PKCS#11 or KMS where supported (ADR-0005). The
  passphrase, MongoDB URI, operator key and HSM PIN are Kubernetes Secrets
  referenced by name, never values in chart values or logs.
- The listener terminates TLS itself and is kept end-to-end through any
  ingress (passthrough or TCP routing). ML-KEM hybrid key exchange is on by
  default in the Go TLS stack.

### Storage topology

- `bolt` (default): embedded store on a PVC, exactly one replica, `Recreate`
  rollouts. The chart refuses any other replica count. Suited to evaluation and
  single-node self-hosted installs.
- `mongo`: documents, key envelopes and the audit chain live in MongoDB
  (ADR-0010), replicas are stateless and `replicas: N` is valid, with a PDB and
  topology spread. Root initialization runs once as a pre-install/pre-upgrade
  hook Job (`init --if-needed`, never regenerates an existing root) so replicas
  cannot race to create two roots. Mongo mode requires an existing passphrase
  Secret and an operator key Secret.

### Bootstrap credential

- The operator API key is adopted from a file
  (`MNEMOCA_BOOTSTRAP_API_KEY_FILE`, mounted from a Secret) whenever the store
  has no operator key: on first start, and as audited recovery if every
  operator key is lost. It is stored hashed; the plaintext is never printed.
  Consequence: after rotating keys, the Secret must be rotated or removed,
  because a restart with no operator key left re-adopts the file's key even if
  it was revoked earlier.
- Without a file, the embedded store mints a key into a 0600 file in the data
  directory. The shared stores refuse to auto-mint: replicas cannot share a
  local file, and printing the key would put it in log pipelines.
- Creation is an atomic insert-if-absent in the store, so concurrent replicas
  create exactly one bootstrap key. The creation is audited at least once: a
  failed audit write is repaired by the next start, and a crash between the
  audit write and the "audited" flag repeats the record.
- Keys are rotated and revoked through the operator API. The count of live
  operator keys is a store document changed by atomic read-modify-write, so
  concurrent revocations, even from different replicas, cannot remove the last
  operator key through the API. Direct store edits are outside that guarantee,
  and the bootstrap file is the recovery path.

### NetworkPolicy defaults

The chart's NetworkPolicy is on by default and deny-first:

- Ingress: nothing, until `networkPolicy.ingressFrom` names the allowed
  namespaces or pods (the MnemoShare namespaces and, if used, an ACME client
  namespace).
- Egress: DNS, MongoDB (when used) and optional HSM/KMS peers. Port 80 is
  blocked, so ACME http-01 validation does not work by default; dns-01 is the
  default-safe path. `acmeEgress` opts in to http-01 towards public addresses
  only (internal ranges excepted; an empty destination list is rejected).
  Independently, the server's http-01 dialer refuses non-public addresses after
  DNS resolution (rebinding-safe) unless `MNEMOCA_ACME_ALLOW_PRIVATE` is set.

## Consequences

- The default install is safe but not usable until the operator supplies a
  passphrase Secret, a listener certificate and an ingress allow-list; the
  evaluation values opt in to generated secrets explicitly because offline
  rendering cannot see existing ones.
- Any install that ran a release before 0.1.3 must rotate its operator key
  (the key was logged); see the README upgrade note.
- Step-CA tenant migration is a separate runbook; this ADR only fixes where the
  replacement sits and what it trusts.
