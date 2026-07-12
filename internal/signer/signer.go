// Package signer defines MnemoCA's pluggable signing backend interface
// (ADR-0005) and the built-in software key backend. HSM (PKCS#11) and cloud
// KMS backends implement the same Backend interface.
package signer

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// ErrNotImplemented is returned by stub backends (pkcs11, kms) until their
// hardware integrations land.
var ErrNotImplemented = errors.New("signer: backend not implemented")

// Signer is a handle to a signing key. The pkix builder decides whether Sign
// receives a digest (classical) or the full message (ML-DSA, Ed25519,
// composite); backends never make that choice.
type Signer interface {
	crypto.Signer
	Algorithm() pkix.Algorithm
}

// KeyRef is an opaque, persistable reference to a key within a backend,
// e.g. "softkey:tenants/acme/issuing.key" or "pkcs11:token=hsm1;label=root".
type KeyRef string

// Scheme returns the backend scheme of the reference.
func (r KeyRef) Scheme() string {
	s, _, ok := strings.Cut(string(r), ":")
	if !ok {
		return ""
	}
	return s
}

// Backend creates, opens, and destroys keys.
type Backend interface {
	Name() string
	Generate(ctx context.Context, alg pkix.Algorithm, label string) (Signer, KeyRef, error)
	Open(ctx context.Context, ref KeyRef) (Signer, error)
	Destroy(ctx context.Context, ref KeyRef) error
}

// Registry routes KeyRefs to backends by scheme.
type Registry struct {
	backends map[string]Backend
}

// NewRegistry builds a registry over the given backends.
func NewRegistry(backends ...Backend) *Registry {
	r := &Registry{backends: make(map[string]Backend)}
	for _, b := range backends {
		r.backends[b.Name()] = b
	}
	return r
}

// Backend returns the backend registered under name.
func (r *Registry) Backend(name string) (Backend, error) {
	b, ok := r.backends[name]
	if !ok {
		return nil, fmt.Errorf("signer: unknown backend %q", name)
	}
	return b, nil
}

// Open resolves ref to its backend and opens the key.
func (r *Registry) Open(ctx context.Context, ref KeyRef) (Signer, error) {
	b, err := r.Backend(ref.Scheme())
	if err != nil {
		return nil, err
	}
	return b.Open(ctx, ref)
}
