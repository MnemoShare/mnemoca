package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/store"
	"github.com/mnemoshare/mnemoca/internal/store/storetest"
)

func doReq(h http.Handler, method, path, key, body string) (int, string) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func jsonField(t *testing.T, body, field string) string {
	t.Helper()
	m := regexpField(field).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("field %s missing in response", field)
	}
	return m[1]
}

// twoOperators returns handlers (one per env) plus the two operator keys and
// ids, where the second key was created through the first.
func twoOperators(t *testing.T, envs []*ca.Env) (hs []http.Handler, keys, ids [2]string) {
	t.Helper()
	for _, e := range envs {
		h, err := New(e, Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey)})
		if err != nil {
			t.Fatal(err)
		}
		hs = append(hs, h)
	}
	code, body := doReq(hs[0], "POST", "/api/v1/apikeys", testBootstrapKey, `{"role":"operator"}`)
	if code != http.StatusCreated {
		t.Fatalf("create second operator: %d %s", code, body)
	}
	keys = [2]string{testBootstrapKey, jsonField(t, body, "key")}
	ids = [2]string{"0123456789abcdef", jsonField(t, body, "id")}
	return
}

func countOperators(t *testing.T, s store.Store) int {
	t.Helper()
	n := 0
	err := store.ForEachJSON(context.Background(), s, apiKeysBucket, func(_ string, k apiKey) error {
		if k.Role == roleOperator {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func raceRevokes(t *testing.T, hs []http.Handler, keys, ids [2]string) (codes [2]int) {
	t.Helper()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// Key i revokes the other key through its own replica.
			codes[i], _ = doReq(hs[i%len(hs)], "DELETE", "/api/v1/apikeys/"+ids[1-i], keys[i], "")
		}()
	}
	close(start)
	wg.Wait()
	return codes
}

func assertOneWins(t *testing.T, codes [2]int, s store.Store) {
	t.Helper()
	ok, refused := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusNoContent:
			ok++
		case http.StatusConflict, http.StatusUnauthorized:
			refused++
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	if ok != 1 || refused != 1 {
		t.Fatalf("codes = %v, want exactly one 204 and one refusal", codes)
	}
	if n := countOperators(t, s); n != 1 {
		t.Fatalf("operator keys left = %d, want 1", n)
	}
}

func TestConcurrentRevokeKeepsOneOperatorBolt(t *testing.T) {
	for i := 0; i < 25; i++ {
		env := boltEnv(t)
		hs, keys, ids := twoOperators(t, []*ca.Env{env})
		assertOneWins(t, raceRevokes(t, hs, keys, ids), env.Store)
	}
}

func TestConcurrentRevokeKeepsOneOperatorMongoReplicas(t *testing.T) {
	for round := 0; round < 8; round++ {
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
		a := open()
		initEnv(t, a)
		b := open()
		t.Cleanup(func() { _ = b.Close() })
		hs, keys, ids := twoOperators(t, []*ca.Env{a, b})
		assertOneWins(t, raceRevokes(t, hs, keys, ids), a.Store)
	}
}

func TestBootstrapFileRecoversWhenNoOperatorKeyRemains(t *testing.T) {
	env := boltEnv(t)
	rec := &recordingAudit{}
	env.Manager.Audit = rec
	opts := Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey)}
	h, err := New(env, opts)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := doReq(h, "POST", "/api/v1/tenants", testBootstrapKey, `{"id":"t1","name":"T1","alg":"ecdsa-p256"}`); code != http.StatusCreated {
		t.Fatalf("tenant: %d %s", code, body)
	}
	if code, body := doReq(h, "POST", "/api/v1/apikeys", testBootstrapKey, `{"role":"tenant","tenant":"t1"}`); code != http.StatusCreated {
		t.Fatalf("tenant key: %d %s", code, body)
	}
	// Simulate the HA race outcome: every operator key gone, tenant key left.
	if err := env.Store.Delete(context.Background(), apiKeysBucket, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if code, _ := doReq(h, "GET", "/api/v1/tenants", testBootstrapKey, ""); code != http.StatusUnauthorized {
		t.Fatalf("precondition: deleted key still authenticates (%d)", code)
	}

	h2, err := New(env, opts)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := doReq(h2, "GET", "/api/v1/tenants", testBootstrapKey, ""); code != http.StatusOK {
		t.Fatalf("recovered key status = %d, want 200", code)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for _, r := range rec.records {
		if r.Action == "apikey.bootstrap.recover" && r.Detail["recovery"] == "true" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("recovery audit records = %d, want 1", n)
	}
}

func TestBootstrapRecoveryWithoutFile(t *testing.T) {
	env := boltEnv(t)
	h, err := New(env, Options{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.Dir, BootstrapKeyFileName)
	data, _ := os.ReadFile(path)
	key := strings.TrimSpace(string(data))
	if code, body := doReq(h, "POST", "/api/v1/tenants", key, `{"id":"t1","name":"T1","alg":"ecdsa-p256"}`); code != http.StatusCreated {
		t.Fatalf("tenant: %d %s", code, body)
	}
	if code, _ := doReq(h, "POST", "/api/v1/apikeys", key, `{"role":"tenant","tenant":"t1"}`); code != http.StatusCreated {
		t.Fatal("tenant key")
	}
	_ = env.Store.Delete(context.Background(), apiKeysBucket, bootstrapMintedID)
	_ = os.Remove(path)

	// Embedded store: re-mints. Shared store: refuses without a file.
	if _, err := New(env, Options{}); err != nil {
		t.Fatalf("bolt must re-mint: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("re-minted key file missing: %v", err)
	}

	env2 := boltEnv(t)
	h2, _ := New(env2, Options{})
	d2, _ := os.ReadFile(filepath.Join(env2.Dir, BootstrapKeyFileName))
	k2 := strings.TrimSpace(string(d2))
	doReq(h2, "POST", "/api/v1/tenants", k2, `{"id":"t1","name":"T1","alg":"ecdsa-p256"}`)
	doReq(h2, "POST", "/api/v1/apikeys", k2, `{"role":"tenant","tenant":"t1"}`)
	_ = env2.Store.Delete(context.Background(), apiKeysBucket, bootstrapMintedID)
	env2.DB = "mongo"
	if _, err := New(env2, Options{}); err == nil {
		t.Fatal("shared store must refuse to auto-mint when only tenant keys remain")
	}
}

func TestRevokeBootstrapKeyDeletesMintedFile(t *testing.T) {
	env := boltEnv(t)
	h, err := New(env, Options{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.Dir, BootstrapKeyFileName)
	data, _ := os.ReadFile(path)
	boot := strings.TrimSpace(string(data))
	code, body := doReq(h, "POST", "/api/v1/apikeys", boot, `{"role":"operator"}`)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	second := jsonField(t, body, "key")
	if code, _ := doReq(h, "DELETE", "/api/v1/apikeys/"+bootstrapMintedID, second, ""); code != http.StatusNoContent {
		t.Fatalf("revoke = %d", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("minted key file survived revocation (err=%v)", err)
	}
}

type failingDelete struct {
	store.Store
	fail bool
}

func (f *failingDelete) Delete(ctx context.Context, path []string, key string) error {
	if f.fail && len(path) > 0 && path[0] == "apikeys" {
		return errors.New("disk on fire")
	}
	return f.Store.Delete(ctx, path, key)
}

func TestRevokeFailureIsAuditedAndRetryable(t *testing.T) {
	env := boltEnv(t)
	rec := &recordingAudit{}
	env.Manager.Audit = rec
	fs := &failingDelete{Store: env.Store}
	env.Store = fs
	h, err := New(env, Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey)})
	if err != nil {
		t.Fatal(err)
	}
	code, body := doReq(h, "POST", "/api/v1/apikeys", testBootstrapKey, `{"role":"operator"}`)
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	second := jsonField(t, body, "key")
	fs.fail = true
	if code, _ := doReq(h, "DELETE", "/api/v1/apikeys/0123456789abcdef", second, ""); code != http.StatusInternalServerError {
		t.Fatalf("revoke with failing delete = %d, want 500", code)
	}
	if code, _ := doReq(h, "GET", "/api/v1/tenants", testBootstrapKey, ""); code != http.StatusOK {
		t.Fatal("key must still authenticate after a failed revoke")
	}
	rec.mu.Lock()
	var actions []string
	for _, r := range rec.records {
		if strings.HasPrefix(r.Action, "apikey.revoke") {
			actions = append(actions, r.Action)
		}
	}
	rec.mu.Unlock()
	if len(actions) != 2 || actions[0] != "apikey.revoke" || actions[1] != "apikey.revoke.failed" {
		t.Fatalf("revoke audit actions = %v", actions)
	}
	fs.fail = false
	if code, _ := doReq(h, "DELETE", "/api/v1/apikeys/0123456789abcdef", second, ""); code != http.StatusNoContent {
		t.Fatalf("retry after failure = %d, want 204 (guard count must be restored)", code)
	}
}

func TestBootstrapRestoresMintedFileFromOrphanedTemp(t *testing.T) {
	env := boltEnv(t)
	if _, err := New(env, Options{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.Dir, BootstrapKeyFileName)
	want, _ := os.ReadFile(path)
	// Crash between insert and rename: the key lives only in the temp file.
	orphan := filepath.Join(env.Dir, ".bootstrap-api-key.deadbeefdeadbeef")
	if err := os.Rename(path, orphan); err != nil {
		t.Fatal(err)
	}
	out := captureStd(t, func() {
		if _, err := New(env, Options{}); err != nil {
			t.Fatal(err)
		}
	})
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("minted file not restored (err=%v)", err)
	}
	if keyRe.MatchString(out) {
		t.Fatal("secret in output")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
}

func TestBootstrapReportsMissingMintedFile(t *testing.T) {
	env := boltEnv(t)
	if _, err := New(env, Options{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.Dir, BootstrapKeyFileName)
	_ = os.Remove(path)
	// A temp file whose hash does not match must not be adopted.
	stray := filepath.Join(env.Dir, ".bootstrap-api-key.0000000000000000")
	_ = os.WriteFile(stray, []byte("mnemoca_0000000000000000_"+strings.Repeat("ab", 32)+"\n"), 0o600)
	out := captureStd(t, func() {
		if _, err := New(env, Options{}); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("non-matching temp file was installed")
	}
	if !strings.Contains(out, path) || !strings.Contains(out, "missing") || keyRe.MatchString(out) {
		t.Fatalf("expected a path-only missing-file notice, got %q", out)
	}
}

func TestAuditBootstrapToleratesRevokedKey(t *testing.T) {
	env := boltEnv(t)
	s := &server{env: env}
	if err := s.auditBootstrap(context.Background(), "ffffffffffffffff", false); err != nil {
		t.Fatalf("auditBootstrap on a revoked key = %v, want nil", err)
	}
}

func TestBootstrapNotAdoptedWarningNamesSource(t *testing.T) {
	env := boltEnv(t)
	if _, err := New(env, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"--bootstrap-api-key-file", "$" + BootstrapKeyEnv} {
		out := captureStd(t, func() {
			if _, err := New(env, Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey), BootstrapKeySource: src}); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, src) || !strings.Contains(out, "not adopted") {
			t.Fatalf("warning %q does not name %s", out, src)
		}
	}
}

func regexpField(f string) *regexp.Regexp {
	return regexp.MustCompile(`"` + f + `":\s*"([^"]+)"`)
}
