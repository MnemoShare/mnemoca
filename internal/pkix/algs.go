// Package pkix implements the X.509 layer for MnemoCA: an algorithm registry
// spanning classical, pure ML-DSA (RFC 9881), and composite
// (draft-ietf-lamps-pq-composite-sigs-19) algorithms, and DER builders for
// certificates, CSRs, and CRLs that crypto/x509 cannot produce yet (ADR-0003).
//
// This file is the single point of contact with the ML-DSA implementation
// (filippo.io/mldsa, ADR-0002). When Go 1.27 ships crypto/mldsa, only this
// file changes.
package pkix

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"

	"filippo.io/mldsa"
)

// Algorithm identifies a signature algorithm MnemoCA can issue with or verify.
type Algorithm string

const (
	ECDSAP256 Algorithm = "ecdsa-p256"
	ECDSAP384 Algorithm = "ecdsa-p384"
	Ed25519   Algorithm = "ed25519"
	MLDSA44   Algorithm = "ml-dsa-44"
	MLDSA65   Algorithm = "ml-dsa-65"
	MLDSA87   Algorithm = "ml-dsa-87"

	// RSA subject-key algorithms: MnemoCA issues certificates FOR RSA keys
	// (hardware tokens, TPM attestation keys) but never signs WITH RSA
	// ("RSA verify-only", PLAN §2). Keys below 2048 bits are rejected.
	RSA2048 Algorithm = "rsa-2048"
	RSA3072 Algorithm = "rsa-3072"
	RSA4096 Algorithm = "rsa-4096"

	// RSA signature algorithms, verification-only (CSR self-signatures).
	RSASHA256 Algorithm = "rsa-sha256"
	RSASHA384 Algorithm = "rsa-sha384"
	RSASHA512 Algorithm = "rsa-sha512"

	// Composite algorithms per draft-ietf-lamps-pq-composite-sigs-19.
	// Experimental until the RFC publishes (ADR-0004).
	CompositeMLDSA65ECDSAP256 Algorithm = "composite-draft-19-mldsa65-ecdsa-p256-sha256"
	CompositeMLDSA44Ed25519   Algorithm = "composite-draft-19-mldsa44-ed25519-sha512"
)

// Signature algorithm and public key OIDs.
var (
	// RFC 9881 / NIST CSOR: same OID identifies the key type and signature.
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}

	// draft-ietf-lamps-pq-composite-sigs-19, id-raw-composite-signature arc
	// 1.3.6.1.5.5.7.6.x. Pinned to draft-19 allocations (ADR-0004).
	oidCompositeMLDSA65ECDSAP256 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 45}
	oidCompositeMLDSA44Ed25519   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 39}
)

// Info describes a registered algorithm.
type Info struct {
	Alg    Algorithm
	OID    asn1.ObjectIdentifier
	Hash   crypto.Hash // 0 for message-signing algorithms (ML-DSA, Ed25519, composite)
	PQ     bool        // provides post-quantum security
	Hybrid bool        // composite classical+PQ
	// Experimental algorithms require explicit opt-in (draft-pinned composites).
	Experimental bool
	// KeyOnly marks subject-key algorithms the CA issues for but cannot
	// sign with (RSA).
	KeyOnly bool
	// VerifyOnly marks signature algorithms accepted on CSR self-signatures
	// but never used for CA signing (RSA signatures).
	VerifyOnly bool
}

var registry = map[Algorithm]Info{
	ECDSAP256: {Alg: ECDSAP256, OID: oidECDSAWithSHA256, Hash: crypto.SHA256},
	ECDSAP384: {Alg: ECDSAP384, OID: oidECDSAWithSHA384, Hash: crypto.SHA384},
	Ed25519:   {Alg: Ed25519, OID: oidEd25519},
	MLDSA44:   {Alg: MLDSA44, OID: oidMLDSA44, PQ: true},
	MLDSA65:   {Alg: MLDSA65, OID: oidMLDSA65, PQ: true},
	MLDSA87:   {Alg: MLDSA87, OID: oidMLDSA87, PQ: true},
	CompositeMLDSA65ECDSAP256: {
		Alg: CompositeMLDSA65ECDSAP256, OID: oidCompositeMLDSA65ECDSAP256,
		PQ: true, Hybrid: true, Experimental: true,
	},
	CompositeMLDSA44Ed25519: {
		Alg: CompositeMLDSA44Ed25519, OID: oidCompositeMLDSA44Ed25519,
		PQ: true, Hybrid: true, Experimental: true,
	},
}

// auxRegistry holds RSA key-only and verify-only entries, kept out of
// Algorithms() so CA/root algorithm enumeration stays sign-capable-only.
var auxRegistry = map[Algorithm]Info{
	RSA2048: {Alg: RSA2048, KeyOnly: true},
	RSA3072: {Alg: RSA3072, KeyOnly: true},
	RSA4096: {Alg: RSA4096, KeyOnly: true},
	RSASHA256: {
		Alg: RSASHA256, Hash: crypto.SHA256, VerifyOnly: true,
		OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
	},
	RSASHA384: {
		Alg: RSASHA384, Hash: crypto.SHA384, VerifyOnly: true,
		OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12},
	},
	RSASHA512: {
		Alg: RSASHA512, Hash: crypto.SHA512, VerifyOnly: true,
		OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13},
	},
}

// Lookup returns registry information for alg.
func Lookup(alg Algorithm) (Info, error) {
	if info, ok := registry[alg]; ok {
		return info, nil
	}
	if info, ok := auxRegistry[alg]; ok {
		return info, nil
	}
	return Info{}, fmt.Errorf("pkix: unknown algorithm %q", alg)
}

// Algorithms lists the sign-capable algorithms (valid for CA keys).
func Algorithms() []Algorithm {
	out := make([]Algorithm, 0, len(registry))
	for alg := range registry {
		out = append(out, alg)
	}
	return out
}

// KeyAlgorithms lists all algorithms a subject key may use (sign-capable
// plus RSA key-only), for profile AllowedKeyAlgs and keygen.
func KeyAlgorithms() []Algorithm {
	out := Algorithms()
	for alg, info := range auxRegistry {
		if info.KeyOnly {
			out = append(out, alg)
		}
	}
	return out
}

// ByOID resolves a signature algorithm OID to a registered algorithm.
func ByOID(oid asn1.ObjectIdentifier) (Info, error) {
	for _, info := range registry {
		if info.OID.Equal(oid) {
			return info, nil
		}
	}
	for _, info := range auxRegistry {
		if len(info.OID) > 0 && info.OID.Equal(oid) {
			return info, nil
		}
	}
	return Info{}, fmt.Errorf("pkix: unknown signature algorithm OID %v", oid)
}

func mldsaParams(alg Algorithm) *mldsa.Parameters {
	switch alg {
	case MLDSA44:
		return mldsa.MLDSA44()
	case MLDSA65:
		return mldsa.MLDSA65()
	case MLDSA87:
		return mldsa.MLDSA87()
	}
	return nil
}

// GenerateKey creates a new private key for alg. The returned key implements
// crypto.Signer. For composite algorithms it returns a *CompositeKey.
func GenerateKey(alg Algorithm) (crypto.Signer, error) {
	switch alg {
	case ECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case MLDSA44, MLDSA65, MLDSA87:
		return mldsa.GenerateKey(mldsaParams(alg))
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case CompositeMLDSA65ECDSAP256:
		return generateCompositeKey(alg, MLDSA65, ECDSAP256)
	case CompositeMLDSA44Ed25519:
		return generateCompositeKey(alg, MLDSA44, Ed25519)
	}
	return nil, fmt.Errorf("pkix: cannot generate key for %q", alg)
}

// NewMLDSAPrivateKey reconstructs an ML-DSA private key from its 32-byte seed.
func NewMLDSAPrivateKey(alg Algorithm, seed []byte) (crypto.Signer, error) {
	params := mldsaParams(alg)
	if params == nil {
		return nil, fmt.Errorf("pkix: %q is not an ML-DSA algorithm", alg)
	}
	return mldsa.NewPrivateKey(params, seed)
}

// AlgorithmForKey reports the registered algorithm of a public key.
func AlgorithmForKey(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return ECDSAP256, nil
		case elliptic.P384():
			return ECDSAP384, nil
		}
		return "", fmt.Errorf("pkix: unsupported ECDSA curve %s", k.Curve.Params().Name)
	case ed25519.PublicKey:
		return Ed25519, nil
	case *rsa.PublicKey:
		switch bits := k.N.BitLen(); {
		case bits >= 4096:
			return RSA4096, nil
		case bits >= 3072:
			return RSA3072, nil
		case bits >= 2048:
			return RSA2048, nil
		default:
			return "", fmt.Errorf("pkix: RSA keys below 2048 bits are not accepted (got %d)", bits)
		}
	case *mldsa.PublicKey:
		switch k.Parameters().String() {
		case mldsa.MLDSA44().String():
			return MLDSA44, nil
		case mldsa.MLDSA65().String():
			return MLDSA65, nil
		case mldsa.MLDSA87().String():
			return MLDSA87, nil
		}
		return "", fmt.Errorf("pkix: unknown ML-DSA parameter set")
	case *CompositePublicKey:
		return k.Alg, nil
	}
	return "", fmt.Errorf("pkix: unsupported public key type %T", pub)
}

// signTBS signs message (the DER TBS bytes) with signer using alg's rules:
// digest-then-sign for ECDSA, direct message signing for Ed25519, ML-DSA and
// composites.
func signTBS(signer crypto.Signer, alg Algorithm, message []byte) ([]byte, error) {
	info, err := Lookup(alg)
	if err != nil {
		return nil, err
	}
	if info.KeyOnly || info.VerifyOnly {
		return nil, fmt.Errorf("pkix: %q is not a CA signing algorithm (RSA is verify-only)", alg)
	}
	switch {
	case info.Hash != 0:
		var digest []byte
		switch info.Hash {
		case crypto.SHA256:
			d := sha256.Sum256(message)
			digest = d[:]
		case crypto.SHA384:
			d := sha512.Sum384(message)
			digest = d[:]
		default:
			return nil, fmt.Errorf("pkix: unsupported hash %v", info.Hash)
		}
		return signer.Sign(rand.Reader, digest, info.Hash)
	default:
		// Message-signing algorithms: Ed25519, ML-DSA (empty context per
		// RFC 9881), and composite (context handled inside CompositeKey).
		return signer.Sign(rand.Reader, message, crypto.Hash(0))
	}
}

// VerifyRawSignature verifies sig over message for the given algorithm and
// key. For digest-based algorithms (ECDSA) message is hashed internally;
// message-signing algorithms (Ed25519, ML-DSA, composite) sign message
// directly. Used by the audit chain and inspection tooling.
func VerifyRawSignature(pub crypto.PublicKey, alg Algorithm, message, sig []byte) error {
	return verifySignature(pub, alg, message, sig)
}

// verifySignature verifies sig over message for the given algorithm and key.
func verifySignature(pub crypto.PublicKey, alg Algorithm, message, sig []byte) error {
	switch alg {
	case ECDSAP256, ECDSAP384:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("pkix: key type %T does not match %q", pub, alg)
		}
		var digest []byte
		if alg == ECDSAP256 {
			d := sha256.Sum256(message)
			digest = d[:]
		} else {
			d := sha512.Sum384(message)
			digest = d[:]
		}
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return fmt.Errorf("pkix: invalid ECDSA signature")
		}
		return nil
	case Ed25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("pkix: key type %T does not match %q", pub, alg)
		}
		if !ed25519.Verify(k, message, sig) {
			return fmt.Errorf("pkix: invalid Ed25519 signature")
		}
		return nil
	case MLDSA44, MLDSA65, MLDSA87:
		k, ok := pub.(*mldsa.PublicKey)
		if !ok {
			return fmt.Errorf("pkix: key type %T does not match %q", pub, alg)
		}
		return mldsa.Verify(k, message, sig, nil)
	case CompositeMLDSA65ECDSAP256, CompositeMLDSA44Ed25519:
		k, ok := pub.(*CompositePublicKey)
		if !ok {
			return fmt.Errorf("pkix: key type %T does not match %q", pub, alg)
		}
		return k.verify(message, sig)
	case RSASHA256, RSASHA384, RSASHA512:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("pkix: key type %T does not match %q", pub, alg)
		}
		if _, err := AlgorithmForKey(k); err != nil {
			return err // enforces the 2048-bit floor
		}
		info := auxRegistry[alg]
		h := info.Hash.New()
		h.Write(message)
		if err := rsa.VerifyPKCS1v15(k, info.Hash, h.Sum(nil), sig); err != nil {
			return fmt.Errorf("pkix: invalid RSA signature: %w", err)
		}
		return nil
	}
	return fmt.Errorf("pkix: cannot verify algorithm %q", alg)
}
