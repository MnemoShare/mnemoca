package pkix

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// Certificate wraps a parsed certificate of any registered algorithm. Fields
// crypto/x509 cannot represent (ML-DSA/composite keys and signatures) are
// carried alongside the leniently-parsed *x509.Certificate.
type Certificate struct {
	Raw []byte
	// X509 is the stdlib view. For PQ certificates its PublicKey is nil and
	// SignatureAlgorithm is UnknownSignatureAlgorithm; all name/validity/
	// extension fields remain valid.
	X509 *x509.Certificate
	// Algorithm is the signature algorithm the certificate was signed with.
	Algorithm Algorithm
	// PublicKey is the subject public key (never nil).
	PublicKey crypto.PublicKey
	// PublicKeyAlgorithm is the algorithm of PublicKey.
	PublicKeyAlgorithm Algorithm
}

// tbsCertificate mirrors RFC 5280 TBSCertificate for DER construction.
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm algorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	Extensions         []stdpkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type certificateDER struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	SignatureValue     asn1.BitString
}

// SubjectKeyID computes the RFC 5280 §4.2.1.2 method-1 key identifier
// (SHA-1 of the SPKI subjectPublicKey BIT STRING contents).
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := MarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var s spki
	if _, err := asn1.Unmarshal(der, &s); err != nil {
		return nil, err
	}
	sum := sha1.Sum(s.PublicKey.RightAlign())
	return sum[:], nil
}

// CreateCertificate issues a certificate for pub from template, signed by
// signer using sigAlg. issuer is nil for self-signed (root) certificates.
// Classical-only requests (classical sigAlg and classical pub) are delegated
// to crypto/x509 for byte-identical stdlib behavior (ADR-0003).
func CreateCertificate(template *x509.Certificate, issuer *Certificate, pub crypto.PublicKey, signer crypto.Signer, sigAlg Algorithm) (*Certificate, error) {
	sigInfo, err := Lookup(sigAlg)
	if err != nil {
		return nil, err
	}
	pubAlg, err := AlgorithmForKey(pub)
	if err != nil {
		return nil, err
	}
	pubInfo, err := Lookup(pubAlg)
	if err != nil {
		return nil, err
	}

	// Ensure a subject key identifier derived from the real key.
	if len(template.SubjectKeyId) == 0 {
		ski, err := SubjectKeyID(pub)
		if err != nil {
			return nil, err
		}
		template.SubjectKeyId = ski
	}

	if !sigInfo.PQ && !pubInfo.PQ {
		return createClassical(template, issuer, pub, signer, sigAlg)
	}

	// PQ path: assemble the TBSCertificate ourselves, reusing stdlib encoding
	// for the subject name and all extensions via a throwaway classical cert.
	subjectDER, extensions, err := harvestTemplate(template, issuer)
	if err != nil {
		return nil, err
	}

	issuerDER := subjectDER // self-signed
	if issuer != nil {
		issuerDER = issuer.X509.RawSubject
	}

	spkiDER, err := MarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sigAlgID, err := signatureAlgorithmIdentifier(sigAlg)
	if err != nil {
		return nil, err
	}

	tbs := tbsCertificate{
		Version:            2, // X.509 v3
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: sigAlgID,
		Issuer:             asn1.RawValue{FullBytes: issuerDER},
		Validity: validity{
			NotBefore: template.NotBefore.UTC(),
			NotAfter:  template.NotAfter.UTC(),
		},
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		PublicKey:  asn1.RawValue{FullBytes: spkiDER},
		Extensions: extensions,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("pkix: marshaling TBSCertificate: %w", err)
	}

	sig, err := signTBS(signer, sigAlg, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("pkix: signing certificate: %w", err)
	}
	certDER, err := asn1.Marshal(certificateDER{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: sigAlgID,
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, fmt.Errorf("pkix: marshaling certificate: %w", err)
	}
	return ParseCertificate(certDER)
}

func createClassical(template *x509.Certificate, issuer *Certificate, pub crypto.PublicKey, signer crypto.Signer, sigAlg Algorithm) (*Certificate, error) {
	switch sigAlg {
	case ECDSAP256:
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
	case ECDSAP384:
		template.SignatureAlgorithm = x509.ECDSAWithSHA384
	case Ed25519:
		template.SignatureAlgorithm = x509.PureEd25519
	default:
		return nil, fmt.Errorf("pkix: %q is not a classical signature algorithm", sigAlg)
	}
	parent := template
	if issuer != nil {
		parent = issuer.X509
		if len(template.AuthorityKeyId) == 0 {
			template.AuthorityKeyId = issuer.X509.SubjectKeyId
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return ParseCertificate(der)
}

// harvestTemplate produces the stdlib-encoded subject RDN and extension list
// for template by issuing a throwaway self-signed classical certificate and
// extracting them. SubjectKeyId/AuthorityKeyId are set explicitly beforehand
// so nothing in the harvested output derives from the throwaway key.
func harvestTemplate(template *x509.Certificate, issuer *Certificate) ([]byte, []stdpkix.Extension, error) {
	tmp := *template
	tmp.SignatureAlgorithm = x509.ECDSAWithSHA256
	if issuer != nil && len(tmp.AuthorityKeyId) == 0 {
		tmp.AuthorityKeyId = issuer.X509.SubjectKeyId
	}
	if len(tmp.AuthorityKeyId) == 0 {
		tmp.AuthorityKeyId = tmp.SubjectKeyId
	}
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmp, &tmp, throwaway.Public(), throwaway)
	if err != nil {
		return nil, nil, fmt.Errorf("pkix: encoding template: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return parsed.RawSubject, parsed.Extensions, nil
}

// ParseCertificate parses a DER certificate of any registered algorithm.
func ParseCertificate(der []byte) (*Certificate, error) {
	xc, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	var outer certificateDER
	if rest, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, fmt.Errorf("pkix: invalid certificate structure: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("pkix: trailing data after certificate")
	}
	sigInfo, err := ByOID(outer.SignatureAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	pub, err := ParsePublicKey(xc.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("pkix: parsing subject public key: %w", err)
	}
	pubAlg, err := AlgorithmForKey(pub)
	if err != nil {
		return nil, err
	}
	return &Certificate{
		Raw:                der,
		X509:               xc,
		Algorithm:          sigInfo.Alg,
		PublicKey:          pub,
		PublicKeyAlgorithm: pubAlg,
	}, nil
}

// CheckSignatureFrom verifies that cert was signed by issuer.
func (c *Certificate) CheckSignatureFrom(issuer *Certificate) error {
	if !bytes.Equal(c.X509.RawIssuer, issuer.X509.RawSubject) {
		return fmt.Errorf("pkix: issuer name mismatch")
	}
	return verifySignature(issuer.PublicKey, c.Algorithm, c.X509.RawTBSCertificate, c.X509.Signature)
}

// VerifyChain checks a leaf-to-root chain (each element signed by the next,
// last element self-signed), including validity windows at time now.
func VerifyChain(chain []*Certificate, now time.Time) error {
	if len(chain) == 0 {
		return fmt.Errorf("pkix: empty chain")
	}
	for i, c := range chain {
		if now.Before(c.X509.NotBefore) || now.After(c.X509.NotAfter) {
			return fmt.Errorf("pkix: certificate %d outside validity window", i)
		}
		issuer := c
		if i+1 < len(chain) {
			issuer = chain[i+1]
			if !issuer.X509.IsCA {
				return fmt.Errorf("pkix: certificate %d issuer is not a CA", i)
			}
		}
		if err := c.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("pkix: certificate %d: %w", i, err)
		}
	}
	return nil
}
