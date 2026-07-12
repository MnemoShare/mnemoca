//go:build cgo

package signer

// Real-HSM tests against SoftHSM2. The test binary provisions a throwaway
// SoftHSM token store (SOFTHSM2_CONF pointing at a temp dir) and initializes
// one token with softhsm2-util; every test shares that token and one lazily
// initialized PKCS11 backend, using distinct key labels. If SoftHSM2 or
// softhsm2-util cannot be found the tests skip with the reason.

import (
	"context"
	"crypto"
	"errors"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

const (
	softhsmTokenLabel = "mnemoca-test"
	softhsmPIN        = "1234"
	softhsmSOPIN      = "12345678"
)

var (
	softhsmOnce    sync.Once
	softhsmBackend *PKCS11
	softhsmModule  string
	softhsmErr     error
)

// findSoftHSMModule locates libsofthsm2.so across common install layouts.
func findSoftHSMModule() (string, error) {
	candidates := []string{
		"/opt/homebrew/lib/softhsm/libsofthsm2.so", // Homebrew (Apple Silicon)
		"/usr/local/lib/softhsm/libsofthsm2.so",    // Homebrew (Intel mac), *BSD
		"/usr/lib/softhsm/libsofthsm2.so",          // Debian/Ubuntu
		"/usr/lib64/pkcs11/libsofthsm2.so",         // Fedora/RHEL
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
	}
	if out, err := exec.Command("brew", "--prefix", "softhsm").Output(); err == nil {
		prefix := strings.TrimSpace(string(out))
		candidates = append([]string{filepath.Join(prefix, "lib", "softhsm", "libsofthsm2.so")}, candidates...)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("libsofthsm2.so not found (install SoftHSM2, e.g. `brew install softhsm`); tried %v", candidates)
}

// softhsm returns a shared PKCS11 backend over a freshly initialized SoftHSM
// token, or skips the calling test if SoftHSM2 is unavailable.
func softhsm(t *testing.T) *PKCS11 {
	t.Helper()
	softhsmOnce.Do(func() {
		module, err := findSoftHSMModule()
		if err != nil {
			softhsmErr = err
			return
		}
		util, err := exec.LookPath("softhsm2-util")
		if err != nil {
			softhsmErr = fmt.Errorf("softhsm2-util not on PATH: %w", err)
			return
		}
		dir, err := os.MkdirTemp("", "mnemoca-softhsm-*")
		if err != nil {
			softhsmErr = err
			return
		}
		tokenDir := filepath.Join(dir, "tokens")
		if err := os.MkdirAll(tokenDir, 0o700); err != nil {
			softhsmErr = err
			return
		}
		conf := filepath.Join(dir, "softhsm2.conf")
		confData := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\nlog.level = ERROR\n"
		if err := os.WriteFile(conf, []byte(confData), 0o600); err != nil {
			softhsmErr = err
			return
		}
		// Process-wide on purpose: SoftHSM reads SOFTHSM2_CONF at
		// C_Initialize, and the module stays loaded for the whole test
		// binary. The temp store is discarded with the temp dir.
		if err := os.Setenv("SOFTHSM2_CONF", conf); err != nil {
			softhsmErr = err
			return
		}
		out, err := exec.Command(util, "--init-token", "--free",
			"--label", softhsmTokenLabel, "--pin", softhsmPIN, "--so-pin", softhsmSOPIN).CombinedOutput()
		if err != nil {
			softhsmErr = fmt.Errorf("softhsm2-util --init-token: %v: %s", err, out)
			return
		}
		softhsmModule = module
		softhsmBackend, softhsmErr = NewPKCS11(PKCS11Config{
			ModulePath: module,
			TokenLabel: softhsmTokenLabel,
			PIN:        softhsmPIN,
		})
	})
	if softhsmErr != nil {
		t.Skipf("SoftHSM2 unavailable: %v", softhsmErr)
	}
	return softhsmBackend
}

// hashFor digests msg per the algorithm's registered hash, mirroring what the
// pkix layer hands classical signers.
func hashFor(t *testing.T, alg pkix.Algorithm, msg []byte) ([]byte, crypto.Hash) {
	t.Helper()
	switch alg {
	case pkix.ECDSAP256:
		d := sha256.Sum256(msg)
		return d[:], crypto.SHA256
	case pkix.ECDSAP384:
		d := sha512.Sum384(msg)
		return d[:], crypto.SHA384
	}
	t.Fatalf("hashFor: unsupported algorithm %q", alg)
	return nil, 0
}

func TestPKCS11GenerateSignVerify(t *testing.T) {
	backend := softhsm(t)
	ctx := context.Background()

	for _, alg := range []pkix.Algorithm{pkix.ECDSAP256, pkix.ECDSAP384} {
		t.Run(string(alg), func(t *testing.T) {
			label := "gen-" + string(alg)
			key, ref, err := backend.Generate(ctx, alg, label)
			if err != nil {
				t.Fatalf("Generate(%s): %v", alg, err)
			}
			t.Cleanup(func() { _ = backend.Destroy(ctx, ref) })

			wantRef := KeyRef(fmt.Sprintf("pkcs11:module=%s;token=%s;label=%s",
				softhsmModule, softhsmTokenLabel, label))
			if ref != wantRef {
				t.Fatalf("ref = %q, want %q", ref, wantRef)
			}
			if got := key.Algorithm(); got != alg {
				t.Fatalf("Algorithm() = %q, want %q", got, alg)
			}

			pub, ok := key.Public().(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("Public() = %T, want *ecdsa.PublicKey", key.Public())
			}
			digest, hash := hashFor(t, alg, []byte("mnemoca pkcs11 to-be-signed"))
			sig, err := key.Sign(rand.Reader, digest, hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !ecdsa.VerifyASN1(pub, digest, sig) {
				t.Fatal("stdlib ecdsa.VerifyASN1 rejected the on-token signature")
			}
		})
	}
}

func TestPKCS11OpenRoundTrip(t *testing.T) {
	backend := softhsm(t)
	ctx := context.Background()

	generated, ref, err := backend.Generate(ctx, pkix.ECDSAP256, "open-p256")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { _ = backend.Destroy(ctx, ref) })

	opened, err := backend.Open(ctx, ref)
	if err != nil {
		t.Fatalf("Open(%q): %v", ref, err)
	}
	if got := opened.Algorithm(); got != pkix.ECDSAP256 {
		t.Fatalf("opened Algorithm() = %q, want %q", got, pkix.ECDSAP256)
	}
	genPub := generated.Public().(*ecdsa.PublicKey)
	openPub, ok := opened.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("opened Public() = %T, want *ecdsa.PublicKey", opened.Public())
	}
	if !genPub.Equal(openPub) {
		t.Fatal("opened key has a different public key than the generated one")
	}

	// A signature from the opened handle must verify under the original
	// public key: it is the same on-token private key.
	digest, hash := hashFor(t, pkix.ECDSAP256, []byte("round trip"))
	sig, err := opened.Sign(rand.Reader, digest, hash)
	if err != nil {
		t.Fatalf("Sign via opened handle: %v", err)
	}
	if !ecdsa.VerifyASN1(genPub, digest, sig) {
		t.Fatal("signature from opened handle does not verify under generated public key")
	}
}

func TestPKCS11GenerateDuplicateLabelFails(t *testing.T) {
	backend := softhsm(t)
	ctx := context.Background()

	_, ref, err := backend.Generate(ctx, pkix.ECDSAP256, "dup-p256")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	t.Cleanup(func() { _ = backend.Destroy(ctx, ref) })

	if _, _, err := backend.Generate(ctx, pkix.ECDSAP256, "dup-p256"); err == nil {
		t.Fatal("Generate with duplicate label succeeded, want error")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate-label error = %v, want mention of already exists", err)
	}
}

func TestPKCS11Destroy(t *testing.T) {
	backend := softhsm(t)
	ctx := context.Background()

	_, ref, err := backend.Generate(ctx, pkix.ECDSAP256, "destroy-p256")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := backend.Destroy(ctx, ref); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := backend.Open(ctx, ref); err == nil {
		t.Fatal("Open succeeded after Destroy, want error")
	}
	if err := backend.Destroy(ctx, ref); err == nil {
		t.Fatal("second Destroy succeeded, want not-found error")
	}
}

func TestPKCS11MLDSAUnsupported(t *testing.T) {
	backend := softhsm(t)
	ctx := context.Background()

	for _, alg := range []pkix.Algorithm{pkix.MLDSA44, pkix.MLDSA65, pkix.MLDSA87} {
		_, _, err := backend.Generate(ctx, alg, "mldsa-"+string(alg))
		if err == nil {
			t.Fatalf("Generate(%s) succeeded on PKCS#11, want error", alg)
		}
		for _, want := range []string{"CKM_ML_DSA", "softkey", "mixed backends"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Generate(%s) error = %v, want mention of %q", alg, err, want)
			}
		}
	}
}

func TestPKCS11CompositeAndEd25519Unsupported(t *testing.T) {
	backend := softhsm(t)
	ctx := context.Background()

	for _, alg := range []pkix.Algorithm{pkix.CompositeMLDSA65ECDSAP256, pkix.CompositeMLDSA44Ed25519} {
		if _, _, err := backend.Generate(ctx, alg, "composite"); err == nil {
			t.Fatalf("Generate(%s) succeeded on PKCS#11, want error", alg)
		} else if !strings.Contains(err.Error(), "composite") {
			t.Errorf("Generate(%s) error = %v, want mention of composite", alg, err)
		}
	}
	if _, _, err := backend.Generate(ctx, pkix.Ed25519, "ed25519"); err == nil {
		t.Fatal("Generate(ed25519) succeeded on PKCS#11, want error")
	} else if !strings.Contains(err.Error(), "crypto11") {
		t.Errorf("Generate(ed25519) error = %v, want mention of crypto11", err)
	}
}

// TestPKCS11ZeroValueIsUnconfiguredStub pins the compatibility contract for
// registry wiring that predates configuration (signer.PKCS11{} in env.go):
// the zero value is a valid Backend whose operations fail with an error
// wrapping ErrNotImplemented, like the pre-HSM stub did.
func TestPKCS11ZeroValueIsUnconfiguredStub(t *testing.T) {
	var backend Backend = PKCS11{}
	if got := backend.Name(); got != "pkcs11" {
		t.Fatalf("Name() = %q, want pkcs11", got)
	}
	if _, _, err := backend.Generate(context.Background(), pkix.ECDSAP256, "x"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("zero-value Generate error = %v, want ErrNotImplemented", err)
	}
	if _, err := backend.Open(context.Background(), "pkcs11:module=/m.so;token=t;label=l"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("zero-value Open error = %v, want ErrNotImplemented", err)
	}
	if err := backend.Destroy(context.Background(), "pkcs11:module=/m.so;token=t;label=l"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("zero-value Destroy error = %v, want ErrNotImplemented", err)
	}
}

func TestPKCS11OpenRejectsForeignRefs(t *testing.T) {
	backend := softhsm(t)
	ctx := context.Background()

	cases := []KeyRef{
		"softkey:tenants/acme/issuing.key",
		"pkcs11:module=/other/lib.so;token=" + softhsmTokenLabel + ";label=x",
		"pkcs11:module=" + KeyRef(softhsmModule) + ";token=other-token;label=x",
	}
	for _, ref := range cases {
		if _, err := backend.Open(ctx, ref); err == nil {
			t.Errorf("Open(%q) succeeded, want error", ref)
		}
	}
}
