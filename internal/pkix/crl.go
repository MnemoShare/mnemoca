package pkix

import (
	"crypto"
	stdpkix "crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// RevokedEntry is one revoked certificate in a CRL.
type RevokedEntry struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	ReasonCode     int
}

// CRL is a parsed certificate revocation list.
type CRL struct {
	Raw        []byte
	Algorithm  Algorithm
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    []RevokedEntry

	rawTBS    []byte
	signature []byte
}

type tbsCertList struct {
	Version             int `asn1:"optional,default:0"`
	Signature           algorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time
	RevokedCertificates []revokedCertificate `asn1:"optional"`
	Extensions          []stdpkix.Extension  `asn1:"optional,explicit,tag:0"`
}

type revokedCertificate struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	Extensions     []stdpkix.Extension `asn1:"optional"`
}

type certificateListDER struct {
	TBSCertList asn1.RawValue
	SigAlg      algorithmIdentifier
	Signature   asn1.BitString
}

var (
	oidExtensionAKI       = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionCRLNumber = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtensionReason    = asn1.ObjectIdentifier{2, 5, 29, 21}
)

type authorityKeyID struct {
	ID []byte `asn1:"optional,tag:0"`
}

// CreateCRL builds and signs a v2 CRL for issuer. One code path serves all
// registered algorithms; verification lives in this package too, so no
// stdlib CRL machinery is involved.
func CreateCRL(issuer *Certificate, signer crypto.Signer, sigAlg Algorithm, revoked []RevokedEntry, number *big.Int, thisUpdate, nextUpdate time.Time) (*CRL, error) {
	sigAlgID, err := signatureAlgorithmIdentifier(sigAlg)
	if err != nil {
		return nil, err
	}

	akiDER, err := asn1.Marshal(authorityKeyID{ID: issuer.X509.SubjectKeyId})
	if err != nil {
		return nil, err
	}
	numDER, err := asn1.Marshal(number)
	if err != nil {
		return nil, err
	}
	exts := []stdpkix.Extension{
		{Id: oidExtensionAKI, Value: akiDER},
		{Id: oidExtensionCRLNumber, Value: numDER},
	}

	entries := make([]revokedCertificate, 0, len(revoked))
	for _, r := range revoked {
		rc := revokedCertificate{
			SerialNumber:   r.SerialNumber,
			RevocationTime: r.RevocationTime.UTC(),
		}
		if r.ReasonCode != 0 {
			reasonDER, err := asn1.Marshal(asn1.Enumerated(r.ReasonCode))
			if err != nil {
				return nil, err
			}
			rc.Extensions = []stdpkix.Extension{{Id: oidExtensionReason, Value: reasonDER}}
		}
		entries = append(entries, rc)
	}

	tbs := tbsCertList{
		Version:             1, // v2
		Signature:           sigAlgID,
		Issuer:              asn1.RawValue{FullBytes: issuer.X509.RawSubject},
		ThisUpdate:          thisUpdate.UTC(),
		NextUpdate:          nextUpdate.UTC(),
		RevokedCertificates: entries,
		Extensions:          exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("pkix: marshaling TBSCertList: %w", err)
	}
	sig, err := signTBS(signer, sigAlg, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("pkix: signing CRL: %w", err)
	}
	crlDER, err := asn1.Marshal(certificateListDER{
		TBSCertList: asn1.RawValue{FullBytes: tbsDER},
		SigAlg:      sigAlgID,
		Signature:   asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	if err != nil {
		return nil, err
	}
	return ParseCRL(crlDER)
}

// ParseCRL parses a DER CRL of any registered algorithm.
func ParseCRL(der []byte) (*CRL, error) {
	var outer certificateListDER
	if rest, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, fmt.Errorf("pkix: invalid CRL: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("pkix: trailing data after CRL")
	}
	sigInfo, err := ByOID(outer.SigAlg.Algorithm)
	if err != nil {
		return nil, err
	}
	var tbs tbsCertList
	if _, err := asn1.Unmarshal(outer.TBSCertList.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("pkix: invalid TBSCertList: %w", err)
	}
	out := &CRL{
		Raw:        der,
		Algorithm:  sigInfo.Alg,
		ThisUpdate: tbs.ThisUpdate,
		NextUpdate: tbs.NextUpdate,
		rawTBS:     outer.TBSCertList.FullBytes,
		signature:  outer.Signature.RightAlign(),
	}
	for _, ext := range tbs.Extensions {
		if ext.Id.Equal(oidExtensionCRLNumber) {
			out.Number = new(big.Int)
			if _, err := asn1.Unmarshal(ext.Value, &out.Number); err != nil {
				return nil, fmt.Errorf("pkix: invalid CRL number: %w", err)
			}
		}
	}
	for _, rc := range tbs.RevokedCertificates {
		entry := RevokedEntry{SerialNumber: rc.SerialNumber, RevocationTime: rc.RevocationTime}
		for _, ext := range rc.Extensions {
			if ext.Id.Equal(oidExtensionReason) {
				var reason asn1.Enumerated
				if _, err := asn1.Unmarshal(ext.Value, &reason); err == nil {
					entry.ReasonCode = int(reason)
				}
			}
		}
		out.Revoked = append(out.Revoked, entry)
	}
	return out, nil
}

// CheckSignatureFrom verifies the CRL signature against issuer.
func (c *CRL) CheckSignatureFrom(issuer *Certificate) error {
	return verifySignature(issuer.PublicKey, c.Algorithm, c.rawTBS, c.signature)
}
