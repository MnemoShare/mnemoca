package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
	"github.com/mnemoshare/mnemoca/internal/store/storetest"
)

const testBootstrapKey = "mnemoca_0123456789abcdef_" +
	"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

var keyRe = regexp.MustCompile(`mnemoca_[0-9a-f]+_[0-9a-f]+`)

func writeKeyFile(t *testing.T, key string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "operator-key")
	if err := os.WriteFile(p, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func initEnv(t *testing.T, env *ca.Env) {
	t.Helper()
	t.Cleanup(func() { _ = env.Close() })
	if _, err := env.Init(context.Background(), ca.InitOptions{
		Alg:   pkix.MLDSA65,
		Actor: audit.Actor{Type: "operator", ID: "test"},
	}); err != nil {
		t.Fatal(err)
	}
}

func boltEnv(t *testing.T) *ca.Env {
	t.Helper()
	env, err := ca.OpenEnv(t.TempDir(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	initEnv(t, env)
	return env
}

func captureStd(t *testing.T, fn func()) string {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	fn()
	_ = w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func authStatus(t *testing.T, h http.Handler, key string) int {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestBootstrapFileKeyAdopted(t *testing.T) {
	env := boltEnv(t)
	var h http.Handler
	out := captureStd(t, func() {
		var err error
		h, err = New(env, Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey)})
		if err != nil {
			t.Fatal(err)
		}
	})
	if keyRe.MatchString(out) || strings.Contains(out, testBootstrapKey) {
		t.Fatalf("key leaked to stdout/stderr: %q", out)
	}
	if got := authStatus(t, h, testBootstrapKey); got != http.StatusOK {
		t.Fatalf("adopted key status = %d, want 200", got)
	}
	if _, err := os.Stat(filepath.Join(env.Dir, BootstrapKeyFileName)); !os.IsNotExist(err) {
		t.Fatalf("adopting a supplied key must not write a minted key file (err=%v)", err)
	}
	stored, err := env.Store.Get(context.Background(), apiKeysBucket, "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "00112233445566778899aabbccddeeff") {
		t.Fatal("plaintext secret persisted; must be hashed")
	}
}

func TestBootstrapFileKeyMalformed(t *testing.T) {
	for name, key := range map[string]string{
		"empty":        "",
		"no prefix":    "0123456789abcdef_00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"short secret": "mnemoca_0123456789abcdef_0011",
		"non hex":      "mnemoca_0123456789abcdef_zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"two lines":    testBootstrapKey + "\n" + testBootstrapKey,
	} {
		t.Run(name, func(t *testing.T) {
			env := boltEnv(t)
			if _, err := New(env, Options{BootstrapKeyFile: writeKeyFile(t, key)}); err == nil {
				t.Fatal("malformed bootstrap key accepted")
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		env := boltEnv(t)
		if _, err := New(env, Options{BootstrapKeyFile: filepath.Join(t.TempDir(), "nope")}); err == nil {
			t.Fatal("missing bootstrap key file accepted")
		}
	})
}

func TestBootstrapMintedToFileNotLogs(t *testing.T) {
	env := boltEnv(t)
	var h http.Handler
	out := captureStd(t, func() {
		var err error
		h, err = New(env, Options{})
		if err != nil {
			t.Fatal(err)
		}
	})
	path := filepath.Join(env.Dir, BootstrapKeyFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(string(data))
	if !keyRe.MatchString(key) {
		t.Fatalf("minted key file malformed")
	}
	if strings.Contains(out, key) || keyRe.MatchString(out) {
		t.Fatalf("minted key leaked to stdout/stderr: %q", out)
	}
	if !strings.Contains(out, path) {
		t.Fatalf("expected the key file path in the log, got %q", out)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", info.Mode().Perm())
	}
	if got := authStatus(t, h, key); got != http.StatusOK {
		t.Fatalf("minted key status = %d, want 200", got)
	}

	// Second start: no new key, file untouched.
	if _, err := New(env, Options{}); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(data) {
		t.Fatal("second start replaced the bootstrap key")
	}
}

func TestBootstrapExistingKeysSkipsEverything(t *testing.T) {
	env := boltEnv(t)
	if _, err := New(env, Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey)}); err != nil {
		t.Fatal(err)
	}
	other := "mnemoca_fedcba9876543210_" + strings.Repeat("ab", 32)
	if _, err := New(env, Options{BootstrapKeyFile: writeKeyFile(t, other)}); err != nil {
		t.Fatal(err)
	}
	n := 0
	_ = store.ForEachJSON(context.Background(), env.Store, apiKeysBucket, func(string, apiKey) error { n++; return nil })
	if n != 1 {
		t.Fatalf("keys = %d, want 1", n)
	}
}

func TestBootstrapMongoModeRefusesAutoMint(t *testing.T) {
	env := boltEnv(t)
	env.DB = "mongo"
	out := captureStd(t, func() {
		if _, err := New(env, Options{}); err == nil {
			t.Error("mongo mode minted/continued without a bootstrap key file")
		}
	})
	if keyRe.MatchString(out) {
		t.Fatalf("secret in output: %q", out)
	}
	if _, err := os.Stat(filepath.Join(env.Dir, BootstrapKeyFileName)); !os.IsNotExist(err) {
		t.Fatal("mongo mode wrote a key file")
	}
}

func TestBootstrapConcurrentSingleKey(t *testing.T) {
	cases := map[string]func(t *testing.T) []*ca.Env{
		"bolt-shared-env": func(t *testing.T) []*ca.Env { e := boltEnv(t); return []*ca.Env{e, e, e, e, e, e, e, e} },
		"mongo-replicas": func(t *testing.T) []*ca.Env {
			uri, db := storetest.TempDB(t)
			open := func() *ca.Env {
				e, err := ca.OpenEnvConfig(context.Background(), ca.Config{
					Dir: t.TempDir(), Passphrase: []byte("test"), DB: "mongo", MongoURI: uri, MongoDB: db,
				})
				if err != nil {
					t.Fatal(err)
				}
				return e
			}
			first := open()
			initEnv(t, first)
			envs := []*ca.Env{first}
			for i := 1; i < 6; i++ {
				e := open()
				t.Cleanup(func() { _ = e.Close() })
				envs = append(envs, e)
			}
			return envs
		},
	}
	for name, mk := range cases {
		for _, mode := range []string{"file", "mint"} {
			if mode == "mint" && strings.HasPrefix(name, "mongo") {
				continue // mongo refuses auto-mint by design
			}
			t.Run(name+"/"+mode, func(t *testing.T) {
				envs := mk(t)
				opts := Options{}
				if mode == "file" {
					opts.BootstrapKeyFile = writeKeyFile(t, testBootstrapKey)
				}
				var wg sync.WaitGroup
				errs := make(chan error, len(envs))
				for _, e := range envs {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, err := New(e, opts)
						errs <- err
					}()
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					if err != nil {
						t.Fatal(err)
					}
				}
				n := 0
				_ = store.ForEachJSON(context.Background(), envs[0].Store, apiKeysBucket, func(string, apiKey) error { n++; return nil })
				if n != 1 {
					t.Fatalf("bootstrap keys = %d, want exactly 1", n)
				}
			})
		}
	}
}
