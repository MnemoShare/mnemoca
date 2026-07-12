package signer

import (
	"context"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// PKCS11 is the HSM backend plug point (PKCS#11 3.2 ML-DSA mechanisms).
// It ships as a stub so configuration, KeyRef schemes, and documentation are
// stable now; the hardware integration lands in Phase 5 (ADR-0005).
type PKCS11 struct{}

func (PKCS11) Name() string { return "pkcs11" }

func (PKCS11) Generate(context.Context, pkix.Algorithm, string) (Signer, KeyRef, error) {
	return nil, "", ErrNotImplemented
}

func (PKCS11) Open(context.Context, KeyRef) (Signer, error) { return nil, ErrNotImplemented }

func (PKCS11) Destroy(context.Context, KeyRef) error { return ErrNotImplemented }

// KMS is the cloud KMS backend plug point (AWS KMS / GCP KMS / Azure Key
// Vault as ML-DSA support arrives). Stub for the same reason as PKCS11.
type KMS struct{}

func (KMS) Name() string { return "kms" }

func (KMS) Generate(context.Context, pkix.Algorithm, string) (Signer, KeyRef, error) {
	return nil, "", ErrNotImplemented
}

func (KMS) Open(context.Context, KeyRef) (Signer, error) { return nil, ErrNotImplemented }

func (KMS) Destroy(context.Context, KeyRef) error { return ErrNotImplemented }
