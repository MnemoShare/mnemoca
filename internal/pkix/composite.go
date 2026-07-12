package pkix

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"

	"filippo.io/mldsa"
)

// Composite ML-DSA signatures per draft-ietf-lamps-pq-composite-sigs-19
// (experimental until RFC, ADR-0004).
//
// Wire formats:
//
//	public key  = mldsaPK || tradPK            (raw concatenation)
//	signature   = mldsaSig || tradSig          (ML-DSA length is fixed, split there)
//	M'          = Prefix || Label || len(ctx) || ctx || PH(M)
//
// The ML-DSA component signs M' with the algorithm Label as its FIPS 204
// context string; the traditional component signs M' per its own convention
// (ECDSA over PH'(M'), Ed25519 over M' directly).

// compositePrefix is the ASCII string "CompositeAlgorithmSignatures2025".
var compositePrefix = []byte("CompositeAlgorithmSignatures2025")

type compositeProfile struct {
	mldsaAlg Algorithm
	tradAlg  Algorithm
	label    string      // domain separator, also the ML-DSA context
	preHash  crypto.Hash // PH applied to M before building M'
}

var compositeProfiles = map[Algorithm]compositeProfile{
	CompositeMLDSA65ECDSAP256: {
		mldsaAlg: MLDSA65, tradAlg: ECDSAP256,
		label: "COMPSIG-MLDSA65-ECDSA-P256-SHA256", preHash: crypto.SHA256,
	},
	CompositeMLDSA44Ed25519: {
		mldsaAlg: MLDSA44, tradAlg: Ed25519,
		label: "COMPSIG-MLDSA44-Ed25519-SHA512", preHash: crypto.SHA512,
	},
}

// CompositePublicKey is a composite ML-DSA + traditional public key.
type CompositePublicKey struct {
	Alg   Algorithm
	MLDSA *mldsa.PublicKey
	Trad  crypto.PublicKey
}

// CompositeKey is a composite private key implementing crypto.Signer.
type CompositeKey struct {
	Alg   Algorithm
	MLDSA *mldsa.PrivateKey
	Trad  crypto.Signer
}

func generateCompositeKey(alg, mldsaAlg, tradAlg Algorithm) (*CompositeKey, error) {
	mk, err := GenerateKey(mldsaAlg)
	if err != nil {
		return nil, err
	}
	tk, err := GenerateKey(tradAlg)
	if err != nil {
		return nil, err
	}
	return &CompositeKey{Alg: alg, MLDSA: mk.(*mldsa.PrivateKey), Trad: tk}, nil
}

// NewCompositeKey assembles a composite key from its components, validating
// that they match the profile for alg.
func NewCompositeKey(alg Algorithm, mldsaKey *mldsa.PrivateKey, trad crypto.Signer) (*CompositeKey, error) {
	p, ok := compositeProfiles[alg]
	if !ok {
		return nil, fmt.Errorf("pkix: %q is not a composite algorithm", alg)
	}
	if got, err := AlgorithmForKey(mldsaKey.Public()); err != nil || got != p.mldsaAlg {
		return nil, fmt.Errorf("pkix: composite %q requires ML-DSA component %q", alg, p.mldsaAlg)
	}
	if got, err := AlgorithmForKey(trad.Public()); err != nil || got != p.tradAlg {
		return nil, fmt.Errorf("pkix: composite %q requires traditional component %q", alg, p.tradAlg)
	}
	return &CompositeKey{Alg: alg, MLDSA: mldsaKey, Trad: trad}, nil
}

func (k *CompositeKey) Public() crypto.PublicKey {
	return &CompositePublicKey{
		Alg:   k.Alg,
		MLDSA: k.MLDSA.PublicKey(),
		Trad:  k.Trad.Public(),
	}
}

// messagePrime builds M' = Prefix || Label || len(ctx) || ctx || PH(M).
// MnemoCA does not use application contexts for certificates, so ctx is empty.
func (p compositeProfile) messagePrime(message []byte) ([]byte, error) {
	var ph []byte
	switch p.preHash {
	case crypto.SHA256:
		d := sha256.Sum256(message)
		ph = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(message)
		ph = d[:]
	default:
		return nil, fmt.Errorf("pkix: unsupported composite pre-hash %v", p.preHash)
	}
	out := make([]byte, 0, len(compositePrefix)+len(p.label)+1+len(ph))
	out = append(out, compositePrefix...)
	out = append(out, p.label...)
	out = append(out, 0) // len(ctx) — empty context
	out = append(out, ph...)
	return out, nil
}

// Sign implements crypto.Signer over the full message (opts hash must be 0).
func (k *CompositeKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, fmt.Errorf("pkix: composite keys sign messages, not digests")
	}
	p := compositeProfiles[k.Alg]
	mp, err := p.messagePrime(message)
	if err != nil {
		return nil, err
	}
	mldsaSig, err := k.MLDSA.Sign(rand.Reader, mp, &mldsa.Options{Context: p.label})
	if err != nil {
		return nil, err
	}
	tradSig, err := signTradComponent(k.Trad, p.tradAlg, mp)
	if err != nil {
		return nil, err
	}
	return append(mldsaSig, tradSig...), nil
}

func signTradComponent(signer crypto.Signer, alg Algorithm, mp []byte) ([]byte, error) {
	switch alg {
	case ECDSAP256:
		d := sha256.Sum256(mp)
		return signer.Sign(rand.Reader, d[:], crypto.SHA256)
	case Ed25519:
		return signer.Sign(rand.Reader, mp, crypto.Hash(0))
	}
	return nil, fmt.Errorf("pkix: unsupported composite traditional component %q", alg)
}

// verify checks a composite signature; both components must verify.
func (pub *CompositePublicKey) verify(message, sig []byte) error {
	p, ok := compositeProfiles[pub.Alg]
	if !ok {
		return fmt.Errorf("pkix: %q is not a composite algorithm", pub.Alg)
	}
	sigSize := mldsaParams(p.mldsaAlg).SignatureSize()
	if len(sig) <= sigSize {
		return fmt.Errorf("pkix: composite signature too short")
	}
	mldsaSig, tradSig := sig[:sigSize], sig[sigSize:]
	mp, err := p.messagePrime(message)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(pub.MLDSA, mp, mldsaSig, &mldsa.Options{Context: p.label}); err != nil {
		return fmt.Errorf("pkix: composite ML-DSA component: %w", err)
	}
	switch p.tradAlg {
	case ECDSAP256:
		k, ok := pub.Trad.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("pkix: composite traditional key type %T", pub.Trad)
		}
		d := sha256.Sum256(mp)
		if !ecdsa.VerifyASN1(k, d[:], tradSig) {
			return fmt.Errorf("pkix: composite ECDSA component: invalid signature")
		}
	case Ed25519:
		k, ok := pub.Trad.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("pkix: composite traditional key type %T", pub.Trad)
		}
		if !ed25519.Verify(k, mp, tradSig) {
			return fmt.Errorf("pkix: composite Ed25519 component: invalid signature")
		}
	default:
		return fmt.Errorf("pkix: unsupported composite traditional component %q", p.tradAlg)
	}
	return nil
}

// marshalCompositePublicKey serializes mldsaPK || tradPK.
func marshalCompositePublicKey(pub *CompositePublicKey) ([]byte, error) {
	p, ok := compositeProfiles[pub.Alg]
	if !ok {
		return nil, fmt.Errorf("pkix: %q is not a composite algorithm", pub.Alg)
	}
	var trad []byte
	switch p.tradAlg {
	case ECDSAP256:
		k, ok := pub.Trad.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("pkix: composite traditional key type %T", pub.Trad)
		}
		b, err := k.Bytes() // uncompressed point per draft-19
		if err != nil {
			return nil, err
		}
		trad = b
	case Ed25519:
		k, ok := pub.Trad.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("pkix: composite traditional key type %T", pub.Trad)
		}
		trad = []byte(k)
	default:
		return nil, fmt.Errorf("pkix: unsupported composite traditional component %q", p.tradAlg)
	}
	return append(pub.MLDSA.Bytes(), trad...), nil
}

// parseCompositePublicKey splits mldsaPK || tradPK at the fixed ML-DSA length.
func parseCompositePublicKey(alg Algorithm, raw []byte) (*CompositePublicKey, error) {
	p, ok := compositeProfiles[alg]
	if !ok {
		return nil, fmt.Errorf("pkix: %q is not a composite algorithm", alg)
	}
	params := mldsaParams(p.mldsaAlg)
	if len(raw) <= params.PublicKeySize() {
		return nil, fmt.Errorf("pkix: composite public key too short")
	}
	mldsaRaw, tradRaw := raw[:params.PublicKeySize()], raw[params.PublicKeySize():]
	mk, err := mldsa.NewPublicKey(params, mldsaRaw)
	if err != nil {
		return nil, fmt.Errorf("pkix: composite ML-DSA public key: %w", err)
	}
	var trad crypto.PublicKey
	switch p.tradAlg {
	case ECDSAP256:
		k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), tradRaw)
		if err != nil {
			return nil, fmt.Errorf("pkix: composite ECDSA public key: %w", err)
		}
		trad = k
	case Ed25519:
		if len(tradRaw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pkix: composite Ed25519 public key: wrong length %d", len(tradRaw))
		}
		trad = ed25519.PublicKey(tradRaw)
	default:
		return nil, fmt.Errorf("pkix: unsupported composite traditional component %q", p.tradAlg)
	}
	return &CompositePublicKey{Alg: alg, MLDSA: mk, Trad: trad}, nil
}
