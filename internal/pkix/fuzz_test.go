package pkix

import (
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Fuzz targets for the attacker-controlled DER parsers (ADR-0003: these are
// the surfaces we own instead of the stdlib). Seeds are valid artifacts for
// each registered algorithm so the fuzzer starts deep in the grammar.

func fuzzSeeds(f *testing.F, kind string) {
	f.Helper()
	for _, alg := range Algorithms() {
		key, err := GenerateKey(alg)
		if err != nil {
			f.Fatal(err)
		}
		switch kind {
		case "cert", "spki":
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               stdpkix.Name{CommonName: "fuzz-seed"},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				DNSNames:              []string{"seed.example.com"},
			}
			cert, err := CreateCertificate(tmpl, nil, key.Public(), key, alg)
			if err != nil {
				f.Fatal(err)
			}
			if kind == "cert" {
				f.Add(cert.Raw)
			} else {
				f.Add(cert.X509.RawSubjectPublicKeyInfo)
			}
		case "csr":
			csr, err := CreateCertificateRequest(&x509.CertificateRequest{
				Subject:  stdpkix.Name{CommonName: "fuzz-seed"},
				DNSNames: []string{"seed.example.com"},
			}, key, alg)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(csr.Raw)
		case "crl":
			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               stdpkix.Name{CommonName: "fuzz-seed"},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().Add(time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			}
			ca, err := CreateCertificate(tmpl, nil, key.Public(), key, alg)
			if err != nil {
				f.Fatal(err)
			}
			crl, err := CreateCRL(ca, key, alg, []RevokedEntry{
				{SerialNumber: big.NewInt(42), RevocationTime: time.Now(), ReasonCode: 1},
			}, big.NewInt(1), time.Now(), time.Now().Add(time.Hour))
			if err != nil {
				f.Fatal(err)
			}
			f.Add(crl.Raw)
		}
	}
}

func FuzzParseCertificate(f *testing.F) {
	fuzzSeeds(f, "cert")
	f.Fuzz(func(_ *testing.T, der []byte) {
		cert, err := ParseCertificate(der)
		if err != nil {
			return
		}
		// Successful parses must be internally consistent and re-verifiable
		// without panicking.
		_ = cert.CheckSignatureFrom(cert)
		if _, err := AlgorithmForKey(cert.PublicKey); err != nil {
			panic("parsed certificate with unregistered key algorithm")
		}
	})
}

func FuzzParseCertificateRequest(f *testing.F) {
	fuzzSeeds(f, "csr")
	f.Fuzz(func(_ *testing.T, der []byte) {
		csr, err := ParseCertificateRequest(der)
		if err != nil {
			return
		}
		_ = csr.CheckSignature()
	})
}

func FuzzParseCRL(f *testing.F) {
	fuzzSeeds(f, "crl")
	f.Fuzz(func(_ *testing.T, der []byte) {
		_, _ = ParseCRL(der)
	})
}

func FuzzParsePublicKey(f *testing.F) {
	fuzzSeeds(f, "spki")
	f.Fuzz(func(_ *testing.T, der []byte) {
		pub, err := ParsePublicKey(der)
		if err != nil {
			return
		}
		// Round-trip: anything we parse we must be able to re-marshal.
		if _, err := MarshalPublicKey(pub); err != nil {
			panic("parsed public key failed to re-marshal: " + err.Error())
		}
	})
}
