package mnemoca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateAndRevokeAPIKey(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "abc", "key": "mnemoca_abc_secret", "role": "operator"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, "mnemoca_x_y")

	created, err := c.CreateAPIKey(context.Background(), "operator", "")
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "abc" || created.Key != "mnemoca_abc_secret" || gotPath != "/api/v1/apikeys" || gotAuth != "Bearer mnemoca_x_y" {
		t.Fatalf("create: %+v path=%s auth=%s", created, gotPath, gotAuth)
	}
	if err := c.RevokeAPIKey(context.Background(), "abc"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/v1/apikeys/abc" {
		t.Fatalf("revoke: %s %s", gotMethod, gotPath)
	}
}

func TestRevokeAPIKeyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"last operator key"}`))
	}))
	t.Cleanup(srv.Close)
	err := New(srv.URL, "k").RevokeAPIKey(context.Background(), "abc")
	var apiErr *APIError
	if e, ok := err.(*APIError); ok {
		apiErr = e
	}
	if apiErr == nil || apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("err = %v, want 409 APIError", err)
	}
}
