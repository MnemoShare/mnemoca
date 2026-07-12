# ADR-0003: Own minimal X.509 DER layer for PQC certificates

**Status:** Accepted
**Date:** 2026-07-11

## Context

Go's `crypto/x509` cannot create or verify certificates signed with ML-DSA or
composite algorithms: `x509.CreateCertificate` rejects unknown signer types, and
the signature-algorithm tables are not extensible. Stdlib PQC X.509 support has
no announced timeline (it is blocked on ecosystem profiles more than on code).

Options considered:

1. **Fork `crypto/x509`.** Full compatibility, but we'd own a drifting copy of
   ~10k lines of stdlib forever. Rejected.
2. **Use CIRCL or another library's x509 fork.** Same drift problem, owned by a
   third party, and ties us to their algorithm surface. Rejected.
3. **Build a minimal DER construction/parsing layer** for exactly the structures
   a CA emits — TBSCertificate, CertificationRequest, CertificateList (CRL) —
   using `golang.org/x/crypto/cryptobyte`, and keep using `crypto/x509`
   unchanged for all-classical certificates and for parsing classical fields.

## Decision

Option 3. `internal/pkix` owns:

- An **algorithm registry** mapping MnemoCA algorithm IDs ⇄ OIDs ⇄ signer/verifier
  functions: classical (ECDSA P-256/P-384, Ed25519), pure ML-DSA per **RFC 9881**
  (OIDs `2.16.840.1.101.3.4.3.{17,18,19}`, absent parameters, BIT STRING raw key),
  and composite per **draft-ietf-lamps-pq-composite-sigs** (ADR-0004).
- A **certificate builder**: constructs TBSCertificate DER (v3, serial, issuer/
  subject, validity, SPKI, extensions incl. SKI/AKI, KeyUsage, EKU, BasicConstraints,
  SANs, CRLDistributionPoints), obtains the signature from a `signer.Signer`, and
  assembles the final Certificate. For classical-only issuance it delegates to
  `x509.CreateCertificate` to keep byte-for-byte stdlib behavior.
- A **CSR layer**: parses PKCS#10 including ML-DSA/composite SPKIs and verifies
  self-signatures; classical CSRs pass through `x509.ParseCertificateRequest`.
- A **CRL builder** with the same signing path.
- **Verification** helpers (chain building for MnemoCA-issued chains, signature
  checks for all registered algorithms) used by tests, `mnemoca inspect`, and
  audit verification.

Parsers of attacker-controlled input (CSR, ACME JWS) get fuzz tests (Phase 5).

## Consequences

- (+) ~1,500 focused lines we fully control; no stdlib fork; new algorithms
  (SLH-DSA later) are registry entries, not surgery.
- (+) Classical behavior stays bit-identical to stdlib.
- (−) We own security-sensitive parsing. Mitigated by cryptobyte (no reflection,
  no encoding/asn1 ambiguity), strict DER, small grammar, fuzzing, and the
  external review in Phase 5.
- (−) `*x509.Certificate` cannot represent an ML-DSA cert's public key/signature
  natively; `pkix.Certificate` wraps raw DER + parsed fields and converts to
  `*x509.Certificate` where classical consumers need it.
