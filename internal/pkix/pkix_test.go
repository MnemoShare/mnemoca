package pkix

import (
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func caTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               stdpkix.Name{CommonName: cn, Organization: []string{"MnemoCA Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func leafTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      stdpkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{cn + ".example.com"},
	}
}

// TestIssueChains issues root → leaf for every registered algorithm and
// verifies chains, PEM round-trips, and cross-checks.
func TestIssueChains(t *testing.T) {
	for _, alg := range Algorithms() {
		t.Run(string(alg), func(t *testing.T) {
			rootKey, err := GenerateKey(alg)
			if err != nil {
				t.Fatalf("GenerateKey(root): %v", err)
			}
			root, err := CreateCertificate(caTemplate("root-"+string(alg)), nil, rootKey.Public(), rootKey, alg)
			if err != nil {
				t.Fatalf("CreateCertificate(root): %v", err)
			}
			if err := root.CheckSignatureFrom(root); err != nil {
				t.Fatalf("root self-signature: %v", err)
			}
			if !root.X509.IsCA {
				t.Fatal("root lost IsCA through PQ encoding path")
			}
			if len(root.X509.SubjectKeyId) == 0 {
				t.Fatal("root missing SubjectKeyId")
			}

			leafKey, err := GenerateKey(alg)
			if err != nil {
				t.Fatalf("GenerateKey(leaf): %v", err)
			}
			leaf, err := CreateCertificate(leafTemplate("leaf-"+string(alg)), root, leafKey.Public(), rootKey, alg)
			if err != nil {
				t.Fatalf("CreateCertificate(leaf): %v", err)
			}
			if err := VerifyChain([]*Certificate{leaf, root}, time.Now()); err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			if got := leaf.X509.DNSNames; len(got) != 1 || got[0] != "leaf-"+string(alg)+".example.com" {
				t.Fatalf("leaf SANs = %v", got)
			}

			// PEM round-trip.
			reparsed, err := ParseCertificatePEM(EncodeCertificatePEM(leaf))
			if err != nil {
				t.Fatalf("PEM round-trip: %v", err)
			}
			if reparsed.Algorithm != alg {
				t.Fatalf("algorithm after round-trip = %q, want %q", reparsed.Algorithm, alg)
			}

			// Tampered TBS must fail verification.
			tampered := *leaf
			tamperedX := *leaf.X509
			tamperedX.RawTBSCertificate = append([]byte(nil), leaf.X509.RawTBSCertificate...)
			tamperedX.RawTBSCertificate[len(tamperedX.RawTBSCertificate)-1] ^= 0xff
			tampered.X509 = &tamperedX
			if err := tampered.CheckSignatureFrom(root); err == nil {
				t.Fatal("tampered certificate verified")
			}
		})
	}
}

// TestMixedChain issues an ECDSA leaf from an ML-DSA issuing CA, the
// cert-manager-with-classical-keys scenario from ADR-0007.
func TestMixedChain(t *testing.T) {
	rootKey, err := GenerateKey(MLDSA87)
	if err != nil {
		t.Fatal(err)
	}
	root, err := CreateCertificate(caTemplate("pq-root"), nil, rootKey.Public(), rootKey, MLDSA87)
	if err != nil {
		t.Fatal(err)
	}
	interKey, err := GenerateKey(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := CreateCertificate(caTemplate("pq-intermediate"), root, interKey.Public(), rootKey, MLDSA87)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := GenerateKey(ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := CreateCertificate(leafTemplate("classical-leaf"), inter, leafKey.Public(), interKey, MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChain([]*Certificate{leaf, inter, root}, time.Now()); err != nil {
		t.Fatalf("mixed chain: %v", err)
	}
	if leaf.PublicKeyAlgorithm != ECDSAP256 || leaf.Algorithm != MLDSA65 {
		t.Fatalf("leaf alg = key %q sig %q", leaf.PublicKeyAlgorithm, leaf.Algorithm)
	}
}

// TestCSRRoundTrip creates and verifies CSRs for each algorithm, including
// SAN extraction on the manual (PQ) parse path.
func TestCSRRoundTrip(t *testing.T) {
	for _, alg := range Algorithms() {
		t.Run(string(alg), func(t *testing.T) {
			key, err := GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			tmpl := &x509.CertificateRequest{
				Subject:        stdpkix.Name{CommonName: "csr-" + string(alg)},
				DNSNames:       []string{"host.example.com"},
				EmailAddresses: []string{"user@example.com"},
				IPAddresses:    []net.IP{net.ParseIP("10.1.2.3").To4()},
			}
			csr, err := CreateCertificateRequest(tmpl, key, alg)
			if err != nil {
				t.Fatalf("CreateCertificateRequest: %v", err)
			}
			parsed, err := ParseCSRPEM(EncodeCSRPEM(csr))
			if err != nil {
				t.Fatalf("ParseCSRPEM: %v", err)
			}
			if err := parsed.CheckSignature(); err != nil {
				t.Fatalf("CheckSignature: %v", err)
			}
			if parsed.Subject.CommonName != "csr-"+string(alg) {
				t.Fatalf("subject CN = %q", parsed.Subject.CommonName)
			}
			if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "host.example.com" {
				t.Fatalf("DNS SANs = %v", parsed.DNSNames)
			}
			if len(parsed.EmailAddresses) != 1 || parsed.EmailAddresses[0] != "user@example.com" {
				t.Fatalf("email SANs = %v", parsed.EmailAddresses)
			}
			if len(parsed.IPAddresses) != 1 || !parsed.IPAddresses[0].Equal(net.ParseIP("10.1.2.3")) {
				t.Fatalf("IP SANs = %v", parsed.IPAddresses)
			}
		})
	}
}

// TestCRLRoundTrip builds, parses, and verifies CRLs for each algorithm.
func TestCRLRoundTrip(t *testing.T) {
	for _, alg := range Algorithms() {
		t.Run(string(alg), func(t *testing.T) {
			key, err := GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := CreateCertificate(caTemplate("crl-"+string(alg)), nil, key.Public(), key, alg)
			if err != nil {
				t.Fatal(err)
			}
			revoked := []RevokedEntry{
				{SerialNumber: big.NewInt(1234), RevocationTime: time.Now(), ReasonCode: 1},
				{SerialNumber: big.NewInt(5678), RevocationTime: time.Now()},
			}
			crl, err := CreateCRL(ca, key, alg, revoked, big.NewInt(7), time.Now(), time.Now().Add(24*time.Hour))
			if err != nil {
				t.Fatalf("CreateCRL: %v", err)
			}
			parsed, err := ParseCRL(crl.Raw)
			if err != nil {
				t.Fatalf("ParseCRL: %v", err)
			}
			if err := parsed.CheckSignatureFrom(ca); err != nil {
				t.Fatalf("CRL signature: %v", err)
			}
			if parsed.Number.Cmp(big.NewInt(7)) != 0 {
				t.Fatalf("CRL number = %v", parsed.Number)
			}
			if len(parsed.Revoked) != 2 || parsed.Revoked[0].SerialNumber.Cmp(big.NewInt(1234)) != 0 || parsed.Revoked[0].ReasonCode != 1 {
				t.Fatalf("revoked entries = %+v", parsed.Revoked)
			}
		})
	}
}

// TestPublicKeySPKIRoundTrip round-trips SPKIs for all algorithms.
func TestPublicKeySPKIRoundTrip(t *testing.T) {
	for _, alg := range Algorithms() {
		t.Run(string(alg), func(t *testing.T) {
			key, err := GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			der, err := MarshalPublicKey(key.Public())
			if err != nil {
				t.Fatalf("MarshalPublicKey: %v", err)
			}
			pub, err := ParsePublicKey(der)
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			got, err := AlgorithmForKey(pub)
			if err != nil || got != alg {
				t.Fatalf("AlgorithmForKey = %q, %v; want %q", got, err, alg)
			}
		})
	}
}
