package signer

import (
	"context"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// KMS is the cloud KMS backend plug point (AWS KMS / GCP KMS / Azure Key
// Vault as ML-DSA support arrives). Stub for the same reason as PKCS11.
type KMS struct{}

func (KMS) Name() string { return "kms" }

func (KMS) Generate(context.Context, pkix.Algorithm, string) (Signer, KeyRef, error) {
	return nil, "", ErrNotImplemented
}

func (KMS) Open(context.Context, KeyRef) (Signer, error) { return nil, ErrNotImplemented }

func (KMS) Destroy(context.Context, KeyRef) error { return ErrNotImplemented }
