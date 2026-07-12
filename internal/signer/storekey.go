package signer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// keysBucket is where storekey envelopes live (path ["keys"], key = label).
var keysBucket = []string{"keys"}

// Storekey is the store-backed key backend for HA deployments (ADR-0010):
// the same scrypt + AES-256-GCM envelope as Softkey, persisted as store
// documents instead of files so every replica opens the same issuing keys.
// KeyRef scheme: "storekey:<label>".
type Storekey struct {
	st         store.Store
	passphrase []byte
}

// NewStorekey creates a storekey backend over st.
func NewStorekey(st store.Store, passphrase []byte) (*Storekey, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("storekey: empty passphrase")
	}
	return &Storekey{st: st, passphrase: passphrase}, nil
}

func (s *Storekey) Name() string { return "storekey" }

// label extracts and validates the key label from a storekey ref.
func (s *Storekey) label(ref KeyRef) (string, error) {
	label := strings.TrimPrefix(string(ref), "storekey:")
	if label == "" || label == string(ref) {
		return "", fmt.Errorf("storekey: invalid key reference %q", ref)
	}
	return label, nil
}

// Generate creates a new key for alg, stores its encrypted envelope under
// label, and returns an open Signer plus its reference.
func (s *Storekey) Generate(ctx context.Context, alg pkix.Algorithm, label string) (Signer, KeyRef, error) {
	if label == "" {
		return nil, "", fmt.Errorf("storekey: empty label")
	}
	key, err := pkix.GenerateKey(alg)
	if err != nil {
		return nil, "", err
	}
	material, err := marshalKeyMaterial(key)
	if err != nil {
		return nil, "", err
	}
	defer zero(material)

	env, err := sealEnvelope(s.passphrase, alg, material)
	if err != nil {
		return nil, "", err
	}
	// Atomic create-if-absent: a concurrent Generate for the same label on
	// another replica must not silently overwrite the winner's key.
	err = store.UpdateJSON(ctx, s.st, keysBucket, label, true, func(existing *envelope) error {
		if existing.Version != 0 {
			return fmt.Errorf("storekey: key %q already exists", label)
		}
		*existing = *env
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return &softSigner{Signer: key, alg: alg}, KeyRef("storekey:" + label), nil
}

// Open loads and decrypts the key at ref.
func (s *Storekey) Open(ctx context.Context, ref KeyRef) (Signer, error) {
	label, err := s.label(ref)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := store.GetJSON(ctx, s.st, keysBucket, label, &env); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("storekey: key %q not found", label)
		}
		return nil, fmt.Errorf("storekey: loading key %q: %w", label, err)
	}
	material, err := unsealEnvelope(s.passphrase, &env)
	if err != nil {
		return nil, err
	}
	defer zero(material)
	key, err := unmarshalKeyMaterial(env.Algorithm, material)
	if err != nil {
		return nil, err
	}
	return &softSigner{Signer: key, alg: env.Algorithm}, nil
}

// Destroy removes the key envelope from the store.
func (s *Storekey) Destroy(ctx context.Context, ref KeyRef) error {
	label, err := s.label(ref)
	if err != nil {
		return err
	}
	return s.st.Delete(ctx, keysBucket, label)
}
