package pkix

import (
	"crypto"
	"encoding/asn1"
	"fmt"

	mldsax509 "filippo.io/mldsa/x509"
)

// spki is the SubjectPublicKeyInfo structure.
type spki struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

// algorithmIdentifier with optional raw parameters (absent for ML-DSA,
// Ed25519, and composite; NULL never emitted per RFC 9881).
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// MarshalPublicKey encodes any registered public key as a DER
// SubjectPublicKeyInfo. Classical and pure ML-DSA keys delegate to
// filippo.io/mldsa/x509 (which itself delegates classical to crypto/x509);
// composite keys are encoded here per draft-19.
func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	if ck, ok := pub.(*CompositePublicKey); ok {
		raw, err := marshalCompositePublicKey(ck)
		if err != nil {
			return nil, err
		}
		info, err := Lookup(ck.Alg)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(spki{
			Algorithm: algorithmIdentifier{Algorithm: info.OID},
			PublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
		})
	}
	return mldsax509.MarshalPKIXPublicKey(pub)
}

// ParsePublicKey decodes a DER SubjectPublicKeyInfo of any registered
// algorithm, including composite keys.
func ParsePublicKey(der []byte) (crypto.PublicKey, error) {
	var s spki
	if rest, err := asn1.Unmarshal(der, &s); err != nil {
		return nil, fmt.Errorf("pkix: invalid SubjectPublicKeyInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("pkix: trailing data after SubjectPublicKeyInfo")
	}
	for alg := range compositeProfiles {
		info := registry[alg]
		if info.OID.Equal(s.Algorithm.Algorithm) {
			return parseCompositePublicKey(alg, s.PublicKey.RightAlign())
		}
	}
	return mldsax509.ParsePKIXPublicKey(der)
}

// signatureAlgorithmIdentifier builds the DER AlgorithmIdentifier that appears
// in the signatureAlgorithm field of certificates/CSRs/CRLs for alg.
// Parameters are absent for all message-signing algorithms; ECDSA-with-SHA2
// also omits parameters per RFC 5758.
func signatureAlgorithmIdentifier(alg Algorithm) (algorithmIdentifier, error) {
	info, err := Lookup(alg)
	if err != nil {
		return algorithmIdentifier{}, err
	}
	return algorithmIdentifier{Algorithm: info.OID}, nil
}
