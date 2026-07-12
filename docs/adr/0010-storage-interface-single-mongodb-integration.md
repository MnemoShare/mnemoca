# ADR-0010: Storage interface with a single external integration (MongoDB via goodm)

**Status:** Accepted
**Date:** 2026-07-12

## Context

v0 shipped on embedded bbolt: zero-dependency, single file, but single-writer —
one pod, no HA. MnemoCA in the `mnemoshare-ca` namespace (and any serious
self-hosted install) needs to run multiple replicas.

The MnemoShare app supports many databases through a heavyweight integration
layer. We explicitly do not want that here: a CA's access patterns are
key-value documents and counters, and every supported database is a permanent
compatibility and testing liability in security-critical code.

HA is not only the document store. Three per-pod states must move behind the
same boundary or replicas diverge:

1. **Documents** (tenants, cert records, ACME objects) — the obvious part.
2. **Keys** — softkey envelopes live on local disk; every replica must open
   the same issuing keys.
3. **Audit chain** — a per-pod JSONL file would fork the hash chain across
   replicas.

## Decision

- **`store.Store` stays a narrow interface** (JSON documents under
  bucket-path/key, atomic read-modify-write, atomic take, iteration, counters,
  nothing else). It is the single seam between MnemoCA and any database.
- **Exactly two implementations**: embedded **bbolt** (default; dev,
  single-node self-hosted) and **MongoDB** via
  `github.com/dwoolworth/goodm` (HA; also matches MnemoShare's operational
  stack — same ODM as idp-lite). No Postgres, no MySQL, no pluggable driver
  matrix. A future customer-driven backend implements one small interface.
- Mongo mapping: one `documents` collection (`{path, key, data}` with a unique
  compound index on `path+key`) and one `counters` collection using atomic
  `$inc`. Deliberately not per-entity collections: the CA queries by key and
  scans by prefix only, and a generic mapping keeps both backends behaviorally
  identical under the same tests. Atomic read-modify-write uses goodm's
  optimistic version (`__v`) with retry; atomic take uses findOneAndDelete.
- **Keys move behind the store in HA mode**: a `storekey` signer backend
  reuses the softkey envelope format (scrypt + AES-256-GCM, ADR-0005) but
  persists envelopes as store documents (`storekey:` KeyRef scheme). Bolt mode
  keeps file-based `softkey` for compatibility.
- **Audit chain moves behind the store in HA mode**: records become store
  documents keyed by zero-padded sequence number; the chain head is a single
  document advanced by compare-and-swap, which serializes appends across
  replicas (losers retry). A crash between head-advance and record-write
  leaves a sequence gap that verification reports precisely — fail-loud, never
  silent. File JSONL remains the bolt-mode format.
- Selection is deployment config, not code: `--db bolt|mongo`
  (`MNEMOCA_DB`, `MNEMOCA_MONGO_URI`, `MNEMOCA_MONGO_DATABASE`). Mongo mode
  implies storekey + store-backed audit; replicas are then stateless.

## Consequences

- (+) `replicas: N` works: random 127-bit serials never collide, CRL numbers
  are atomic counters, ACME nonces become atomic takes (also fixing the
  get-then-delete race noted in the v0 review), audit appends serialize via
  CAS.
- (+) One database to integrate, index, test, and document — per the explicit
  product decision to avoid a multi-database support burden.
- (+) Both backends run the identical test suite through the interface;
  behavior cannot drift unnoticed.
- (−) Mongo becomes a hard dependency of HA deployments (replica-set Mongo is
  already standard MnemoShare infrastructure).
- (−) Generic document mapping trades Mongo-side queryability for backend
  parity — acceptable: the CA never queries inside documents today.
- (−) Audit throughput is bounded by head-CAS contention; at machine-identity
  issuance rates this is far from a bottleneck (ADR-0008 already accepts an
  fsync per issuance).
