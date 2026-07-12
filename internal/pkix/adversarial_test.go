package pkix

// Adversarial / negative-path coverage for the X.509 layer. Every case here
// asserts the SECURE outcome (rejection), not merely the absence of a panic.

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// forgeAlgs is the algorithm matrix used by signature-substitution tests: a
// pure PQ algorithm, a hybrid composite, and a classical algorithm.
var forgeAlgs = []Algorithm{MLDSA65, CompositeMLDSA65ECDSAP256, ECDSAP256}

// TestSignatureFromWrongKeyRejected verifies that a certificate whose
// signature was produced by one key cannot be verified against a DIFFERENT
// key, even when the issuer NAME collides. A legitimately-signed leaf is
// checked against an impostor CA that shares the real issuer's subject name
// but holds a different key — the signature-substitution attack. Covers pure
// PQ, hybrid composite, and classical algorithms.
func TestSignatureFromWrongKeyRejected(t *testing.T) {
	for _, alg := range forgeAlgs {
		t.Run(string(alg), func(t *testing.T) {
			issuerKey, err := GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			issuer, err := CreateCertificate(caTemplate("real-issuer"), nil, issuerKey.Public(), issuerKey, alg)
			if err != nil {
				t.Fatal(err)
			}
			// Impostor CA: identical subject name, different key.
			impostorKey, err := GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			impostor, err := CreateCertificate(caTemplate("real-issuer"), nil, impostorKey.Public(), impostorKey, alg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(issuer.X509.RawSubject, impostor.X509.RawSubject) {
				t.Fatal("precondition: impostor should share the issuer subject name")
			}
			leafKey, err := GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := CreateCertificate(leafTemplate("victim"), issuer, leafKey.Public(), issuerKey, alg)
			if err != nil {
				t.Fatal(err)
			}
			// Sanity: the leaf verifies against its real issuer.
			if err := leaf.CheckSignatureFrom(issuer); err != nil {
				t.Fatalf("legitimate leaf failed against real issuer: %v", err)
			}
			// Attack: the same-named impostor (different key) must be rejected.
			if err := leaf.CheckSignatureFrom(impostor); err == nil {
				t.Fatal("leaf verified against a same-named issuer holding a different key")
			}
		})
	}
}

// TestCompositeOnlyMLDSAValidRejected forges a composite signature that is
// valid under the ML-DSA component but not the ECDSA component, proving both
// components are mandatory (draft-19 §4). The forgery reuses a shared ML-DSA
// component but a mismatched ECDSA component.
func TestCompositeOnlyMLDSAValidRejected(t *testing.T) {
	const alg = CompositeMLDSA65ECDSAP256

	real, err := GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	realKey := real.(*CompositeKey)

	otherEC, err := GenerateKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	// forgedKey shares realKey's ML-DSA component but carries a different
	// ECDSA component.
	forgedKey, err := NewCompositeKey(alg, realKey.MLDSA, otherEC)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("composite adversarial message")
	sig, err := realKey.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: the signature verifies under the real key.
	if err := VerifyRawSignature(realKey.Public(), alg, msg, sig); err != nil {
		t.Fatalf("real composite signature failed to verify: %v", err)
	}
	// Attack: it must NOT verify under a key whose ML-DSA half matches but
	// whose ECDSA half differs.
	if err := VerifyRawSignature(forgedKey.Public(), alg, msg, sig); err == nil {
		t.Fatal("composite signature verified with only the ML-DSA component valid")
	}
}

func validityTemplate(cn string, notBefore, notAfter time.Time) *x509.Certificate {
	tmpl := leafTemplate(cn)
	tmpl.NotBefore = notBefore
	tmpl.NotAfter = notAfter
	return tmpl
}

// TestVerifyChainRejections covers expired, not-yet-valid, non-CA issuer, and
// wrong-issuer-name chains.
func TestVerifyChainRejections(t *testing.T) {
	rootKey, err := GenerateKey(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	root, err := CreateCertificate(caTemplate("chain-root"), nil, rootKey.Public(), rootKey, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	t.Run("expired-leaf", func(t *testing.T) {
		leafKey, _ := GenerateKey(MLDSA65)
		leaf, err := CreateCertificate(
			validityTemplate("expired", now.Add(-48*time.Hour), now.Add(-24*time.Hour)),
			root, leafKey.Public(), rootKey, MLDSA65)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyChain([]*Certificate{leaf, root}, now); err == nil {
			t.Fatal("expired leaf accepted")
		}
	})

	t.Run("not-yet-valid-leaf", func(t *testing.T) {
		leafKey, _ := GenerateKey(MLDSA65)
		leaf, err := CreateCertificate(
			validityTemplate("future", now.Add(24*time.Hour), now.Add(48*time.Hour)),
			root, leafKey.Public(), rootKey, MLDSA65)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyChain([]*Certificate{leaf, root}, now); err == nil {
			t.Fatal("not-yet-valid leaf accepted")
		}
	})

	t.Run("non-CA-issuer", func(t *testing.T) {
		// An issuer whose IsCA is false must not be trusted to sign a child.
		nonCAKey, _ := GenerateKey(MLDSA65)
		nonCATmpl := leafTemplate("non-ca-issuer") // IsCA defaults to false
		nonCA, err := CreateCertificate(nonCATmpl, root, nonCAKey.Public(), rootKey, MLDSA65)
		if err != nil {
			t.Fatal(err)
		}
		leafKey, _ := GenerateKey(MLDSA65)
		leaf, err := CreateCertificate(leafTemplate("child-of-non-ca"), nonCA, leafKey.Public(), nonCAKey, MLDSA65)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyChain([]*Certificate{leaf, nonCA, root}, now); err == nil {
			t.Fatal("chain with a non-CA issuer accepted")
		}
	})

	t.Run("wrong-issuer-name", func(t *testing.T) {
		// Leaf issued by root, but the chain presents an unrelated CA whose
		// subject name does not match the leaf's issuer.
		otherKey, _ := GenerateKey(MLDSA65)
		other, err := CreateCertificate(caTemplate("unrelated-ca"), nil, otherKey.Public(), otherKey, MLDSA65)
		if err != nil {
			t.Fatal(err)
		}
		leafKey, _ := GenerateKey(MLDSA65)
		leaf, err := CreateCertificate(leafTemplate("leaf"), root, leafKey.Public(), rootKey, MLDSA65)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyChain([]*Certificate{leaf, other}, now); err == nil {
			t.Fatal("chain with mismatched issuer name accepted")
		}
	})
}

// TestCSRTamperedSANRejected flips a byte inside a signed SAN and requires the
// self-signature check to fail.
func TestCSRTamperedSANRejected(t *testing.T) {
	key, err := GenerateKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCertificateRequest(&x509.CertificateRequest{
		Subject:  stdpkix.Name{CommonName: "tamper-csr"},
		DNSNames: []string{"adversarialdns.example.com"},
	}, key, ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), csr.Raw...)
	// Flip a byte inside the dNSName GeneralName (raw IA5 bytes, so DER stays
	// structurally valid) — a classic post-signing SAN tamper.
	idx := bytes.Index(raw, []byte("adversarialdns"))
	if idx < 0 {
		t.Fatal("could not locate SAN bytes to tamper")
	}
	raw[idx] ^= 0xff
	tampered, err := ParseCertificateRequest(raw)
	if err != nil {
		t.Fatalf("tampered CSR should still parse (SAN charset unchecked): %v", err)
	}
	if err := tampered.CheckSignature(); err == nil {
		t.Fatal("CSR with a tampered SAN passed signature verification")
	}
}

// TestCSRMalformedInputs feeds truncated, empty, and oversized-garbage DER to
// the CSR parser: each must return an error without panicking.
func TestCSRMalformedInputs(t *testing.T) {
	key, _ := GenerateKey(ECDSAP256)
	csr, err := CreateCertificateRequest(&x509.CertificateRequest{
		Subject: stdpkix.Name{CommonName: "malformed"},
	}, key, ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	garbage := make([]byte, 8192)
	if _, err := rand.Read(garbage); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"truncated": csr.Raw[:len(csr.Raw)/2],
		"empty":     {},
		"garbage":   garbage,
	}
	for name, der := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCertificateRequest(der); err == nil {
				t.Fatal("malformed CSR DER parsed without error")
			}
		})
	}
}

// bogusSigOID is an unallocated OID used to stand in for an unknown signature
// algorithm in the parser-rejection tests.
var bogusSigOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 7}

// TestParseCertificateUnknownSigOID builds a structurally valid certificate
// whose signature OID is unknown to the registry and requires a clean error.
func TestParseCertificateUnknownSigOID(t *testing.T) {
	key, _ := GenerateKey(ECDSAP256)
	cert, err := CreateCertificate(caTemplate("unknown-oid"), nil, key.Public(), key, ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	var outer certificateDER
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	var tbs tbsCertificate
	if _, err := asn1.Unmarshal(outer.TBSCertificate.FullBytes, &tbs); err != nil {
		t.Fatal(err)
	}
	// Swap both the inner and outer signature OIDs so the DER stays internally
	// consistent (only the algorithm is now unknown).
	tbs.SignatureAlgorithm = algorithmIdentifier{Algorithm: bogusSigOID}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	outer.TBSCertificate = asn1.RawValue{FullBytes: tbsDER}
	outer.SignatureAlgorithm = algorithmIdentifier{Algorithm: bogusSigOID}
	forged, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCertificate(forged); err == nil {
		t.Fatal("certificate with unknown signature OID parsed without error")
	}
}

// TestParseCRLUnknownSigOID does the same for CRLs.
func TestParseCRLUnknownSigOID(t *testing.T) {
	key, _ := GenerateKey(ECDSAP256)
	ca, err := CreateCertificate(caTemplate("crl-unknown-oid"), nil, key.Public(), key, ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := CreateCRL(ca, key, ECDSAP256,
		[]RevokedEntry{{SerialNumber: big.NewInt(1), RevocationTime: time.Now()}},
		big.NewInt(1), time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var outer certificateListDER
	if _, err := asn1.Unmarshal(crl.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	outer.SigAlg = algorithmIdentifier{Algorithm: bogusSigOID}
	forged, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCRL(forged); err == nil {
		t.Fatal("CRL with unknown signature OID parsed without error")
	}
}
