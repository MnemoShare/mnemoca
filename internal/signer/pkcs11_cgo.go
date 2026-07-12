//go:build cgo

package signer

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"sync"

	"github.com/ThalesGroup/crypto11"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// errPKCS11Unconfigured is returned by the zero-value PKCS11 backend, which
// exists so registry wiring (signer.PKCS11{}) predates configuration; real
// deployments construct the backend with NewPKCS11.
var errPKCS11Unconfigured = fmt.Errorf(
	"%w: pkcs11 backend not configured; construct it with NewPKCS11 "+
		"(MNEMOCA_PKCS11_MODULE, MNEMOCA_PKCS11_TOKEN, MNEMOCA_PKCS11_PIN)", ErrNotImplemented)

// PKCS11 is the HSM signing backend. It holds CA keys on a PKCS#11 token
// (SoftHSM2, YubiHSM2, AWS CloudHSM, Luna, ...) via ThalesGroup/crypto11 and
// never exports private key material: Sign operations run on-token
// (CKA_SENSITIVE, CKA_EXTRACTABLE=false).
//
// Supported algorithms: ECDSA P-256 and P-384. Ed25519 key generation is not
// implemented by crypto11 (no CKM_EC_EDWARDS_KEY_PAIR_GEN support), and
// ML-DSA is not yet available in crypto11 or SoftHSM even though PKCS#11 3.2
// defines CKM_ML_DSA — see Generate for the guidance errors. MnemoCA supports
// mixed backends, so an HSM-held classical root can coexist with software
// (softkey) ML-DSA keys.
//
// The zero value is a valid Backend that fails every key operation with
// errPKCS11Unconfigured; use NewPKCS11 to configure it. Requires a
// cgo-enabled build; see pkcs11_nocgo.go for the CGO_ENABLED=0 stub.
type PKCS11 struct {
	state *pkcs11State
}

// pkcs11State is the shared mutable state behind a configured backend.
type pkcs11State struct {
	cfg PKCS11Config

	mu  sync.Mutex
	ctx *crypto11.Context // lazily initialized by context()
}

// NewPKCS11 validates cfg and returns a backend. The PKCS#11 module is not
// loaded and no session is opened until the first key operation, so
// constructing the backend is cheap and cannot fail on HSM connectivity.
func NewPKCS11(cfg PKCS11Config) (*PKCS11, error) {
	if cfg.ModulePath == "" {
		return nil, fmt.Errorf("pkcs11: module path is required (MNEMOCA_PKCS11_MODULE)")
	}
	if cfg.TokenLabel == "" {
		return nil, fmt.Errorf("pkcs11: token label is required (MNEMOCA_PKCS11_TOKEN)")
	}
	return &PKCS11{state: &pkcs11State{cfg: cfg}}, nil
}

// Name implements Backend.
func (PKCS11) Name() string { return pkcs11Scheme }

// context returns the crypto11 context, loading the module and logging in on
// first use.
func (s *pkcs11State) context() (*crypto11.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx != nil {
		return s.ctx, nil
	}
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       s.cfg.ModulePath,
		TokenLabel: s.cfg.TokenLabel,
		Pin:        s.cfg.PIN,
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: open module %q token %q: %w", s.cfg.ModulePath, s.cfg.TokenLabel, err)
	}
	s.ctx = ctx
	return ctx, nil
}

// Close releases PKCS#11 sessions and finalizes the module. Safe to call
// multiple times; subsequent key operations reopen the module.
func (p PKCS11) Close() error {
	if p.state == nil {
		return nil
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.ctx == nil {
		return nil
	}
	err := p.state.ctx.Close()
	p.state.ctx = nil
	return err
}

// pkcs11Signer adapts a crypto11 on-token key to signer.Signer. crypto11's
// ECDSA Sign takes a digest (with crypto.SHA256/384 opts, as the pkix layer
// passes for classical algorithms) and returns an ASN.1 DER signature.
type pkcs11Signer struct {
	crypto11.Signer
	alg pkix.Algorithm
}

func (s *pkcs11Signer) Algorithm() pkix.Algorithm { return s.alg }

// unsupportedAlg maps algorithms this backend cannot hold to precise,
// actionable errors. Returns nil for supported algorithms.
func unsupportedAlg(alg pkix.Algorithm, info pkix.Info) error {
	switch {
	case info.Hybrid:
		return fmt.Errorf("pkcs11: composite algorithm %q is not supported on PKCS#11 tokens; "+
			"keep composite keys in the softkey backend", alg)
	case info.PQ:
		return fmt.Errorf("pkcs11: %q is not yet supported on PKCS#11 tokens: PKCS#11 3.2 defines "+
			"CKM_ML_DSA, but crypto11 and SoftHSM do not implement it yet; keep ML-DSA keys in the "+
			"softkey backend — MnemoCA supports mixed backends (e.g. an HSM-held ECDSA-P384 root pair "+
			"alongside software ML-DSA keys)", alg)
	case alg == pkix.Ed25519:
		return fmt.Errorf("pkcs11: ed25519 key generation (CKM_EC_EDWARDS_KEY_PAIR_GEN) is not "+
			"supported by the crypto11 library; use %q or %q on-token, or keep Ed25519 keys in the "+
			"softkey backend", pkix.ECDSAP256, pkix.ECDSAP384)
	}
	return nil
}

// Generate creates an ECDSA key pair on the token under label and returns an
// on-token Signer plus its persistable reference.
func (p PKCS11) Generate(_ context.Context, alg pkix.Algorithm, label string) (Signer, KeyRef, error) {
	if p.state == nil {
		return nil, "", errPKCS11Unconfigured
	}
	info, err := pkix.Lookup(alg)
	if err != nil {
		return nil, "", err
	}
	if err := unsupportedAlg(alg, info); err != nil {
		return nil, "", err
	}
	var curve elliptic.Curve
	switch alg {
	case pkix.ECDSAP256:
		curve = elliptic.P256()
	case pkix.ECDSAP384:
		curve = elliptic.P384()
	default:
		return nil, "", fmt.Errorf("pkcs11: cannot generate key for %q on a PKCS#11 token", alg)
	}

	ref, err := formatPKCS11Ref(p.state.cfg.ModulePath, p.state.cfg.TokenLabel, label)
	if err != nil {
		return nil, "", err
	}
	ctx, err := p.state.context()
	if err != nil {
		return nil, "", err
	}
	existing, err := ctx.FindKeyPairs(nil, []byte(label))
	if err != nil {
		return nil, "", fmt.Errorf("pkcs11: check for existing key %q: %w", label, err)
	}
	if len(existing) > 0 {
		return nil, "", fmt.Errorf("pkcs11: key %q already exists on token %q", label, p.state.cfg.TokenLabel)
	}
	// CKA_ID and CKA_LABEL are both set to label: crypto11 requires a CKA_ID
	// to pair public and private halves, and our refs address keys by label.
	key, err := ctx.GenerateECDSAKeyPairWithLabel([]byte(label), []byte(label), curve)
	if err != nil {
		return nil, "", fmt.Errorf("pkcs11: generate %s key %q: %w", alg, label, err)
	}
	return &pkcs11Signer{Signer: key, alg: alg}, ref, nil
}

// Open finds the key pair addressed by ref on the configured token. The
// algorithm is derived from the on-token public key.
func (p PKCS11) Open(_ context.Context, ref KeyRef) (Signer, error) {
	if p.state == nil {
		return nil, errPKCS11Unconfigured
	}
	label, err := p.refLabel(ref)
	if err != nil {
		return nil, err
	}
	ctx, err := p.state.context()
	if err != nil {
		return nil, err
	}
	key, err := ctx.FindKeyPair(nil, []byte(label))
	if err != nil {
		return nil, fmt.Errorf("pkcs11: open key %q on token %q: %w", label, p.state.cfg.TokenLabel, err)
	}
	alg, err := pkix.AlgorithmForKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("pkcs11: key %q: %w", label, err)
	}
	return &pkcs11Signer{Signer: key, alg: alg}, nil
}

// Destroy deletes the key pair addressed by ref from the token.
func (p PKCS11) Destroy(_ context.Context, ref KeyRef) error {
	if p.state == nil {
		return errPKCS11Unconfigured
	}
	label, err := p.refLabel(ref)
	if err != nil {
		return err
	}
	ctx, err := p.state.context()
	if err != nil {
		return err
	}
	pairs, err := ctx.FindKeyPairs(nil, []byte(label))
	if err != nil {
		return fmt.Errorf("pkcs11: find key %q on token %q: %w", label, p.state.cfg.TokenLabel, err)
	}
	if len(pairs) == 0 {
		return fmt.Errorf("pkcs11: key %q not found on token %q", label, p.state.cfg.TokenLabel)
	}
	for _, pair := range pairs {
		if err := pair.Delete(); err != nil {
			return fmt.Errorf("pkcs11: delete key %q: %w", label, err)
		}
	}
	return nil
}

// refLabel parses ref and verifies it addresses this backend's module and
// token, returning the key label.
func (p PKCS11) refLabel(ref KeyRef) (string, error) {
	module, token, label, err := parsePKCS11Ref(ref)
	if err != nil {
		return "", err
	}
	if module != p.state.cfg.ModulePath {
		return "", fmt.Errorf("pkcs11: reference %q addresses module %q, backend is configured for %q",
			ref, module, p.state.cfg.ModulePath)
	}
	if token != p.state.cfg.TokenLabel {
		return "", fmt.Errorf("pkcs11: reference %q addresses token %q, backend is configured for %q",
			ref, token, p.state.cfg.TokenLabel)
	}
	return label, nil
}
