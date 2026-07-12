package pkix

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"testing"
	"time"
)

// TestRSASubjectKeys covers the Step-CA migration scenario: hardware-style
// RSA-2048 leaf keys receiving certificates from ECDSA and ML-DSA CAs.
// MnemoCA never signs with RSA — only for RSA subject keys.
func TestRSASubjectKeys(t *testing.T) {
	rsaKey, err := GenerateKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := CreateCertificateRequest(&x509.CertificateRequest{
		Subject:  stdpkix.Name{CommonName: "tpm-client"},
		DNSNames: []string{"tpm-client.example.com"},
	}, rsaKey, RSA2048)
	if err != nil {
		t.Fatalf("RSA CSR: %v", err)
	}
	parsed, err := ParseCertificateRequest(csr.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("RSA CSR self-signature: %v", err)
	}
	if parsed.PublicKeyAlgorithm != RSA2048 || parsed.Algorithm != RSASHA256 {
		t.Fatalf("CSR algs = key %q sig %q", parsed.PublicKeyAlgorithm, parsed.Algorithm)
	}

	for _, caAlg := range []Algorithm{ECDSAP384, MLDSA65} {
		t.Run(string(caAlg), func(t *testing.T) {
			caKey, err := GenerateKey(caAlg)
			if err != nil {
				t.Fatal(err)
			}
			root, err := CreateCertificate(caTemplate("rsa-issuer-"+string(caAlg)), nil, caKey.Public(), caKey, caAlg)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := CreateCertificate(leafTemplate("tpm-client"), root, parsed.PublicKey, caKey, caAlg)
			if err != nil {
				t.Fatalf("issuing for RSA key: %v", err)
			}
			if leaf.PublicKeyAlgorithm != RSA2048 || leaf.Algorithm != caAlg {
				t.Fatalf("leaf algs = key %q sig %q", leaf.PublicKeyAlgorithm, leaf.Algorithm)
			}
			if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
				t.Fatalf("leaf public key type %T", leaf.PublicKey)
			}
			if err := VerifyChain([]*Certificate{leaf, root}, time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestRSANeverSigns pins the verify-only policy.
func TestRSANeverSigns(t *testing.T) {
	rsaKey, err := GenerateKey(RSA2048)
	if err != nil {
		t.Fatal(err)
	}
	// As a CA signing algorithm: rejected.
	if _, err := CreateCertificate(caTemplate("rsa-root"), nil, rsaKey.Public(), rsaKey, RSA2048); err == nil {
		t.Fatal("RSA accepted as certificate signing algorithm")
	}
	if _, err := CreateCertificate(caTemplate("rsa-root"), nil, rsaKey.Public(), rsaKey, RSASHA256); err == nil {
		t.Fatal("rsa-sha256 accepted as certificate signing algorithm")
	}
}

// TestRSAWeakKeyRejected pins the 2048-bit floor.
func TestRSAWeakKeyRejected(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AlgorithmForKey(weak.Public()); err == nil {
		t.Fatal("1024-bit RSA key accepted")
	}
}
