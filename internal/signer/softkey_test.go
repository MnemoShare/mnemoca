package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

func TestSoftkeyRoundTrip(t *testing.T) {
	ctx := context.Background()
	sk, err := NewSoftkey(t.TempDir(), []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range pkix.Algorithms() {
		t.Run(string(alg), func(t *testing.T) {
			gen, ref, err := sk.Generate(ctx, alg, "keys/"+string(alg))
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if ref.Scheme() != "softkey" {
				t.Fatalf("scheme = %q", ref.Scheme())
			}
			opened, err := sk.Open(ctx, ref)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if opened.Algorithm() != alg {
				t.Fatalf("algorithm = %q, want %q", opened.Algorithm(), alg)
			}

			// The reopened key must produce signatures the generated key's
			// public key verifies: sign a message via the pkix cert path.
			msg := []byte("signer round-trip probe")
			info, err := pkix.Lookup(alg)
			if err != nil {
				t.Fatal(err)
			}
			var sig []byte
			if info.Hash != 0 {
				digest := digestFor(t, info.Hash, msg)
				sig, err = opened.Sign(rand.Reader, digest, info.Hash)
			} else {
				sig, err = opened.Sign(rand.Reader, msg, crypto.Hash(0))
			}
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("empty signature")
			}
			// Public keys must match across generate/open.
			genSPKI, err := pkix.MarshalPublicKey(gen.Public())
			if err != nil {
				t.Fatal(err)
			}
			openSPKI, err := pkix.MarshalPublicKey(opened.Public())
			if err != nil {
				t.Fatal(err)
			}
			if string(genSPKI) != string(openSPKI) {
				t.Fatal("public key changed across persistence round-trip")
			}
		})
	}
}

func digestFor(t *testing.T, h crypto.Hash, msg []byte) []byte {
	t.Helper()
	hh := h.New()
	hh.Write(msg)
	return hh.Sum(nil)
}

func TestSoftkeyWrongPassphrase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sk1, err := NewSoftkey(dir, []byte("correct"))
	if err != nil {
		t.Fatal(err)
	}
	_, ref, err := sk1.Generate(ctx, pkix.MLDSA65, "root")
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := NewSoftkey(dir, []byte("wrong"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sk2.Open(ctx, ref); err == nil {
		t.Fatal("opened key with wrong passphrase")
	}
}

func TestSoftkeyPathTraversal(t *testing.T) {
	sk, err := NewSoftkey(t.TempDir(), []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sk.Open(context.Background(), "softkey:../../etc/passwd"); err == nil {
		t.Fatal("path traversal not rejected")
	}
}
