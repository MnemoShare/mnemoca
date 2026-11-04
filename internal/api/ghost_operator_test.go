package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/store"
	"github.com/mnemoshare/mnemoca/internal/store/storetest"
)

// hookStore runs fn once, just before the first write to the operator set.
type hookStore struct {
	store.Store
	mu   sync.Mutex
	fn   func()
	done bool
}

func (h *hookStore) Update(ctx context.Context, path []string, key string, create bool, fn func([]byte) ([]byte, error)) error {
	h.mu.Lock()
	run := !h.done && h.fn != nil && len(path) > 0 && path[0] == "apikeys-meta"
	if run {
		h.done = true
	}
	h.mu.Unlock()
	if run {
		h.fn()
	}
	return h.Store.Update(ctx, path, key, create, fn)
}

func operatorIDs(t *testing.T, s store.Store) []string {
	t.Helper()
	var o operatorSet
	if err := store.GetJSON(context.Background(), s, operatorMetaBucket, operatorMetaKey, &o); err != nil {
		t.Fatal(err)
	}
	return o.IDs
}

// A revoke that completes between reconcile's key scan and its write must not
// leave the revoked id in the operator count.
func TestReconcileRacingRevokeLeavesNoGhost(t *testing.T) {
	env := boltEnv(t)
	hs, keys, ids := twoOperators(t, []*ca.Env{env})

	// Fire the revoke when reconcile's CAS begins, i.e. after its scan.
	hook := &hookStore{Store: env.Store}
	hook.fn = func() {
		if code, _ := doReq(hs[0], "DELETE", "/api/v1/apikeys/"+ids[0], keys[1], ""); code != http.StatusNoContent {
			t.Errorf("interleaved revoke = %d", code)
		}
	}
	env.Store = hook
	s := &server{env: env}
	if err := s.reconcileOperators(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := operatorIDs(t, hook.Store); len(got) != 1 || got[0] != ids[1] {
		t.Fatalf("operator set = %v, want only %s", got, ids[1])
	}
	if code, _ := doReq(hs[0], "DELETE", "/api/v1/apikeys/"+ids[1], keys[1], ""); code != http.StatusConflict {
		t.Fatalf("revoking the last operator = %d, want 409", code)
	}
}

type committedDeleteErr struct{ store.Store }

func (c *committedDeleteErr) Delete(ctx context.Context, path []string, key string) error {
	if err := c.Store.Delete(ctx, path, key); err != nil {
		return err
	}
	if len(path) > 0 && path[0] == "apikeys" {
		return errors.New("connection reset after commit")
	}
	return nil
}

func TestRevokeDeleteCommittedButErroredLeavesNoGhost(t *testing.T) {
	env := boltEnv(t)
	hs, keys, ids := twoOperators(t, []*ca.Env{env})
	env.Store = &committedDeleteErr{Store: env.Store}
	if code, _ := doReq(hs[0], "DELETE", "/api/v1/apikeys/"+ids[0], keys[1], ""); code != http.StatusInternalServerError {
		t.Fatalf("revoke = %d, want 500", code)
	}
	if code, _ := doReq(hs[0], "DELETE", "/api/v1/apikeys/"+ids[1], keys[1], ""); code != http.StatusConflict {
		t.Fatalf("last operator revoke = %d, want 409 (ghost id counted)", code)
	}
}

func TestFinishRevokeRemovesIDFromSet(t *testing.T) {
	env := boltEnv(t)
	_, _, ids := twoOperators(t, []*ca.Env{env})
	s := &server{env: env}
	ctx := context.Background()
	if err := s.beginRevoke(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	// A reconcile that already re-added the id must not survive the finish.
	if err := s.updateOperators(ctx, func(o *operatorSet) error { o.IDs = append(o.IDs, ids[0]); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.finishRevoke(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	for _, id := range operatorIDs(t, env.Store) {
		if id == ids[0] {
			t.Fatal("finishRevoke left the revoked id in the set")
		}
	}
}

func TestReconcileHammeredDuringRevokesMongo(t *testing.T) {
	for round := 0; round < 6; round++ {
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

		// Extra operators to revoke while another replica reconciles.
		extra := make([][2]string, 0, 4)
		for i := 0; i < 4; i++ {
			code, body := doReq(hs[0], "POST", "/api/v1/apikeys", keys[0], `{"role":"operator"}`)
			if code != http.StatusCreated {
				t.Fatalf("create extra: %d", code)
			}
			extra = append(extra, [2]string{jsonField(t, body, "id"), jsonField(t, body, "key")})
		}

		stop := make(chan struct{})
		var wg sync.WaitGroup
		sb := &server{env: b}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if err := sb.reconcileOperators(context.Background()); err != nil {
						t.Errorf("reconcile: %v", err)
						return
					}
				}
			}
		}()
		for _, e := range extra {
			if code, _ := doReq(hs[0], "DELETE", "/api/v1/apikeys/"+e[0], keys[0], ""); code != http.StatusNoContent {
				t.Fatalf("revoke extra = %d", code)
			}
		}
		if code, _ := doReq(hs[0], "DELETE", "/api/v1/apikeys/"+ids[1], keys[0], ""); code != http.StatusNoContent {
			t.Fatalf("revoke second = %d", code)
		}
		close(stop)
		wg.Wait()
		time.Sleep(10 * time.Millisecond)

		if n := countOperators(t, a.Store); n != 1 {
			t.Fatalf("round %d: live operators = %d, want 1", round, n)
		}
		if code, _ := doReq(hs[1], "DELETE", "/api/v1/apikeys/"+ids[0], keys[0], ""); code != http.StatusConflict {
			t.Fatalf("round %d: revoking the last operator = %d, want 409 (ghost in count: %s)",
				round, code, strings.Join(operatorIDs(t, a.Store), ","))
		}
	}
}

func TestRecoveryAdoptionWarnsWithKeyIDOnly(t *testing.T) {
	env := boltEnv(t)
	opts := Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey), BootstrapKeySource: "--bootstrap-api-key-file"}
	h, err := New(env, opts)
	if err != nil {
		t.Fatal(err)
	}
	doReq(h, "POST", "/api/v1/tenants", testBootstrapKey, `{"id":"t1","name":"T1","alg":"ecdsa-p256"}`)
	doReq(h, "POST", "/api/v1/apikeys", testBootstrapKey, `{"role":"tenant","tenant":"t1"}`)
	_ = env.Store.Delete(context.Background(), apiKeysBucket, "0123456789abcdef")

	out := captureStd(t, func() {
		if _, err := New(env, opts); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "0123456789abcdef") || !strings.Contains(out, "recover") {
		t.Fatalf("expected a recovery warning naming the key id, got %q", out)
	}
	if strings.Contains(out, "00112233445566778899aabbccddeeff") {
		t.Fatal("secret in recovery warning")
	}
}

func TestMintedInstallRequiresMatchingFile(t *testing.T) {
	env := boltEnv(t)
	path := env.Dir + "/" + BootstrapKeyFileName
	if fileHoldsKeyHash(path, "deadbeef") {
		t.Fatal("missing file reported as holding the key")
	}
	if _, err := New(env, Options{}); err != nil {
		t.Fatal(err)
	}
	var rec apiKey
	if err := store.GetJSON(context.Background(), env.Store, apiKeysBucket, bootstrapMintedID, &rec); err != nil {
		t.Fatal(err)
	}
	if !fileHoldsKeyHash(path, rec.Hash) {
		t.Fatal("installed file does not hold the stored key")
	}
	if fileHoldsKeyHash(path, strings.Repeat("0", 64)) {
		t.Fatal("a different hash must not match")
	}
}
