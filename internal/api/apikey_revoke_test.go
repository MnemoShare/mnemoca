package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevokeAPIKey(t *testing.T) {
	srv, boot := newTestServer(t)

	var second struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	wantStatus(t, call(t, srv, "POST", "/api/v1/apikeys", boot, map[string]any{"role": "operator"}, &second), http.StatusCreated)

	// Revoke the bootstrap key using the new one.
	wantStatus(t, call(t, srv, "DELETE", "/api/v1/apikeys/0123456789abcdef", second.Key, nil, nil), http.StatusNoContent)
	wantStatus(t, call(t, srv, "GET", "/api/v1/tenants", boot, nil, nil), http.StatusUnauthorized)
	wantStatus(t, call(t, srv, "GET", "/api/v1/tenants", second.Key, nil, nil), http.StatusOK)

	// Missing key.
	wantStatus(t, call(t, srv, "DELETE", "/api/v1/apikeys/0123456789abcdef", second.Key, nil, nil), http.StatusNotFound)
	// Last operator key cannot be revoked, even by itself.
	wantStatus(t, call(t, srv, "DELETE", "/api/v1/apikeys/"+second.ID, second.Key, nil, nil), http.StatusConflict)
	wantStatus(t, call(t, srv, "GET", "/api/v1/tenants", second.Key, nil, nil), http.StatusOK)
}

func TestRevokeAPIKeyAuthz(t *testing.T) {
	srv, boot := newTestServer(t)
	wantStatus(t, call(t, srv, "POST", "/api/v1/tenants", boot,
		map[string]any{"id": "t1", "name": "T1", "alg": "ecdsa-p256"}, nil), http.StatusCreated)
	var tk struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	wantStatus(t, call(t, srv, "POST", "/api/v1/apikeys", boot,
		map[string]any{"role": "tenant", "tenant": "t1"}, &tk), http.StatusCreated)

	wantStatus(t, call(t, srv, "DELETE", "/api/v1/apikeys/0123456789abcdef", tk.Key, nil, nil), http.StatusForbidden)
	wantStatus(t, call(t, srv, "DELETE", "/api/v1/apikeys/0123456789abcdef", "", nil, nil), http.StatusUnauthorized)

	// Tenant keys can be revoked while the sole operator key remains.
	wantStatus(t, call(t, srv, "DELETE", "/api/v1/apikeys/"+tk.ID, boot, nil, nil), http.StatusNoContent)
	wantStatus(t, call(t, srv, "GET", "/api/v1/tenants/t1", tk.Key, nil, nil), http.StatusUnauthorized)
}

func TestRevokeAPIKeyAudited(t *testing.T) {
	env := boltEnv(t)
	rec := &recordingAudit{}
	env.Manager.Audit = rec
	h, err := New(env, Options{BootstrapKeyFile: writeKeyFile(t, testBootstrapKey)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	var second struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	wantStatus(t, call(t, srv, "POST", "/api/v1/apikeys", testBootstrapKey, map[string]any{"role": "operator"}, &second), http.StatusCreated)
	wantStatus(t, call(t, srv, "DELETE", "/api/v1/apikeys/0123456789abcdef", second.Key, nil, nil), http.StatusNoContent)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for _, r := range rec.records {
		if r.Action == "apikey.revoke" && r.Object.ID == "0123456789abcdef" && r.Actor.ID == second.ID {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("apikey.revoke records = %d, want 1", n)
	}
}
