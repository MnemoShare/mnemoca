package pkix

import (
	"crypto"
	"encoding/pem"
	"fmt"
)

const (
	pemCertificate = "CERTIFICATE"
	pemCSR         = "CERTIFICATE REQUEST"
	pemCRL         = "X509 CRL"
)

// EncodeCertificatePEM encodes a certificate as PEM.
func EncodeCertificatePEM(c *Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: c.Raw})
}

// EncodeChainPEM encodes a chain as concatenated PEM blocks, leaf first.
func EncodeChainPEM(chain []*Certificate) []byte {
	var out []byte
	for _, c := range chain {
		out = append(out, EncodeCertificatePEM(c)...)
	}
	return out
}

// EncodeCSRPEM encodes a CSR as PEM.
func EncodeCSRPEM(r *CertificateRequest) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCSR, Bytes: r.Raw})
}

// EncodeCRLPEM encodes a CRL as PEM.
func EncodeCRLPEM(c *CRL) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCRL, Bytes: c.Raw})
}

// ParseCertificatePEM parses the first CERTIFICATE block in data.
func ParseCertificatePEM(data []byte) (*Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemCertificate {
		return nil, fmt.Errorf("pkix: no CERTIFICATE PEM block found")
	}
	return ParseCertificate(block.Bytes)
}

// ParseChainPEM parses all CERTIFICATE blocks in data, in order.
func ParseChainPEM(data []byte) ([]*Certificate, error) {
	var chain []*Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != pemCertificate {
			continue
		}
		c, err := ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("pkix: no CERTIFICATE PEM blocks found")
	}
	return chain, nil
}

// ParsePublicKeyPEM parses a PUBLIC KEY block into a registered key type.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("pkix: no PUBLIC KEY PEM block found")
	}
	return ParsePublicKey(block.Bytes)
}

// ParseCSRPEM parses the first CERTIFICATE REQUEST block in data.
func ParseCSRPEM(data []byte) (*CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemCSR {
		return nil, fmt.Errorf("pkix: no CERTIFICATE REQUEST PEM block found")
	}
	return ParseCertificateRequest(block.Bytes)
}
