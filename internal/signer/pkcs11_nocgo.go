//go:build !cgo

package signer

import (
	"context"
	"fmt"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// errPKCS11RequiresCgo explains why HSM operations are unavailable in this
// binary: crypto11 dlopens the PKCS#11 module, which needs cgo.
var errPKCS11RequiresCgo = fmt.Errorf(
	"%w: PKCS#11 HSM support requires a cgo-enabled build (the PKCS#11 module is loaded with dlopen); "+
		"rebuild with CGO_ENABLED=1, or use the softkey backend", ErrNotImplemented)

// PKCS11 is the HSM signing backend. This is the CGO_ENABLED=0 stub used by
// static builds (e.g. the FIPS Docker image): configuration and KeyRef
// parsing work so wiring stays uniform (the zero value is a valid Backend),
// but every key operation reports that HSM support needs a cgo build. The
// real implementation is in pkcs11_cgo.go.
type PKCS11 struct {
	state *pkcs11State
}

// pkcs11State mirrors the cgo implementation's configured state.
type pkcs11State struct {
	cfg PKCS11Config
}

// NewPKCS11 validates cfg and returns the stub backend.
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

// Generate implements Backend; always unavailable without cgo.
func (PKCS11) Generate(context.Context, pkix.Algorithm, string) (Signer, KeyRef, error) {
	return nil, "", errPKCS11RequiresCgo
}

// Open implements Backend; always unavailable without cgo.
func (PKCS11) Open(context.Context, KeyRef) (Signer, error) {
	return nil, errPKCS11RequiresCgo
}

// Destroy implements Backend; always unavailable without cgo.
func (PKCS11) Destroy(context.Context, KeyRef) error {
	return errPKCS11RequiresCgo
}

// Close is a no-op in the non-cgo stub.
func (PKCS11) Close() error { return nil }
