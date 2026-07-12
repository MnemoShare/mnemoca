package pkix

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
)

// CertificateRequest is a parsed PKCS#10 CSR of any registered algorithm.
type CertificateRequest struct {
	Raw                []byte
	Subject            stdpkix.Name
	RawSubject         []byte
	PublicKey          crypto.PublicKey
	PublicKeyAlgorithm Algorithm
	Algorithm          Algorithm // signature algorithm of the self-signature
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	Extensions         []stdpkix.Extension

	rawCRI    []byte
	signature []byte
}

type certificationRequest struct {
	CRI       asn1.RawValue
	SigAlg    algorithmIdentifier
	Signature asn1.BitString
}

type certificationRequestInfo struct {
	Version    int
	Subject    asn1.RawValue
	SPKI       asn1.RawValue
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
}

var (
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidExtensionSAN     = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// CreateCertificateRequest builds a CSR for signer's key, self-signed with
// sigAlg. Classical algorithms delegate to crypto/x509; PQ algorithms reuse
// the stdlib's subject/attribute encoding via a throwaway classical CSR and
// swap in the real SPKI and signature (same technique as CreateCertificate).
func CreateCertificateRequest(template *x509.CertificateRequest, signer crypto.Signer, sigAlg Algorithm) (*CertificateRequest, error) {
	info, err := Lookup(sigAlg)
	if err != nil {
		return nil, err
	}
	if !info.PQ {
		switch sigAlg {
		case ECDSAP256:
			template.SignatureAlgorithm = x509.ECDSAWithSHA256
		case ECDSAP384:
			template.SignatureAlgorithm = x509.ECDSAWithSHA384
		case Ed25519:
			template.SignatureAlgorithm = x509.PureEd25519
		case RSA2048, RSA3072, RSA4096:
			// RSA keys self-sign their CSRs (the CA still signs the
			// certificate with its own algorithm).
			template.SignatureAlgorithm = x509.SHA256WithRSA
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
		if err != nil {
			return nil, err
		}
		return ParseCertificateRequest(der)
	}

	// Throwaway classical CSR to harvest stdlib-encoded subject + attributes.
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmp := *template
	tmp.SignatureAlgorithm = x509.ECDSAWithSHA256
	harvestDER, err := x509.CreateCertificateRequest(rand.Reader, &tmp, throwaway)
	if err != nil {
		return nil, fmt.Errorf("pkix: encoding CSR template: %w", err)
	}
	var harvested certificationRequest
	if _, err := asn1.Unmarshal(harvestDER, &harvested); err != nil {
		return nil, err
	}
	var harvestedCRI certificationRequestInfo
	if _, err := asn1.Unmarshal(harvested.CRI.FullBytes, &harvestedCRI); err != nil {
		return nil, err
	}

	spkiDER, err := MarshalPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	cri := certificationRequestInfo{
		Version:    0,
		Subject:    asn1.RawValue{FullBytes: harvestedCRI.Subject.FullBytes},
		SPKI:       asn1.RawValue{FullBytes: spkiDER},
		Attributes: asn1.RawValue{FullBytes: harvestedCRI.Attributes.FullBytes},
	}
	criDER, err := asn1.Marshal(cri)
	if err != nil {
		return nil, err
	}
	sig, err := signTBS(signer, sigAlg, criDER)
	if err != nil {
		return nil, err
	}
	sigAlgID, err := signatureAlgorithmIdentifier(sigAlg)
	if err != nil {
		return nil, err
	}
	csrDER, err := asn1.Marshal(certificationRequest{
		CRI:       asn1.RawValue{FullBytes: criDER},
		SigAlg:    sigAlgID,
		Signature: asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, err
	}
	return ParseCertificateRequest(csrDER)
}

// ParseCertificateRequest parses a DER CSR of any registered algorithm and
// leaves signature verification to CheckSignature.
func ParseCertificateRequest(der []byte) (*CertificateRequest, error) {
	var req certificationRequest
	if rest, err := asn1.Unmarshal(der, &req); err != nil {
		return nil, fmt.Errorf("pkix: invalid CSR: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("pkix: trailing data after CSR")
	}
	sigInfo, err := ByOID(req.SigAlg.Algorithm)
	if err != nil {
		return nil, err
	}
	var cri certificationRequestInfo
	if _, err := asn1.Unmarshal(req.CRI.FullBytes, &cri); err != nil {
		return nil, fmt.Errorf("pkix: invalid CertificationRequestInfo: %w", err)
	}
	pub, err := ParsePublicKey(cri.SPKI.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("pkix: parsing CSR public key: %w", err)
	}
	pubAlg, err := AlgorithmForKey(pub)
	if err != nil {
		return nil, err
	}

	out := &CertificateRequest{
		Raw:                der,
		RawSubject:         cri.Subject.FullBytes,
		PublicKey:          pub,
		PublicKeyAlgorithm: pubAlg,
		Algorithm:          sigInfo.Alg,
		rawCRI:             req.CRI.FullBytes,
		signature:          req.Signature.RightAlign(),
	}

	var rdn stdpkix.RDNSequence
	if _, err := asn1.Unmarshal(cri.Subject.FullBytes, &rdn); err != nil {
		return nil, fmt.Errorf("pkix: invalid CSR subject: %w", err)
	}
	out.Subject.FillFromRDNSequence(&rdn)

	if err := out.parseAttributes(cri.Attributes); err != nil {
		return nil, err
	}
	return out, nil
}

// parseAttributes extracts the PKCS#9 extensionRequest attribute and the SAN
// extension within it.
func (r *CertificateRequest) parseAttributes(attrs asn1.RawValue) error {
	if len(attrs.Bytes) == 0 {
		return nil
	}
	// Attributes ::= [0] IMPLICIT SET OF Attribute; iterate the SET contents.
	rest := attrs.Bytes
	for len(rest) > 0 {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		var err error
		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			return fmt.Errorf("pkix: invalid CSR attribute: %w", err)
		}
		if !attr.Type.Equal(oidExtensionRequest) {
			continue
		}
		var exts []stdpkix.Extension
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &exts); err != nil {
			return fmt.Errorf("pkix: invalid extensionRequest: %w", err)
		}
		r.Extensions = exts
		for _, ext := range exts {
			if ext.Id.Equal(oidExtensionSAN) {
				if err := r.parseSAN(ext.Value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// parseSAN decodes a GeneralNames SEQUENCE (dNSName, rfc822Name, iPAddress,
// uniformResourceIdentifier).
func (r *CertificateRequest) parseSAN(value []byte) error {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(value, &seq); err != nil {
		return fmt.Errorf("pkix: invalid SAN extension: %w", err)
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &gn)
		if err != nil {
			return fmt.Errorf("pkix: invalid GeneralName: %w", err)
		}
		if gn.Class != asn1.ClassContextSpecific {
			continue
		}
		switch gn.Tag {
		case 1:
			r.EmailAddresses = append(r.EmailAddresses, string(gn.Bytes))
		case 2:
			r.DNSNames = append(r.DNSNames, string(gn.Bytes))
		case 6:
			u, err := url.Parse(string(gn.Bytes))
			if err != nil {
				return fmt.Errorf("pkix: invalid URI SAN: %w", err)
			}
			r.URIs = append(r.URIs, u)
		case 7:
			if len(gn.Bytes) == net.IPv4len || len(gn.Bytes) == net.IPv6len {
				r.IPAddresses = append(r.IPAddresses, net.IP(gn.Bytes))
			}
		}
	}
	return nil
}

// CheckSignature verifies the CSR's self-signature.
func (r *CertificateRequest) CheckSignature() error {
	return verifySignature(r.PublicKey, r.Algorithm, r.rawCRI, r.signature)
}
