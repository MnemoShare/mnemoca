package api

// Adversarial / negative-path coverage for the REST API. Every case asserts a
// rejecting status code (4xx), never a 5xx or success.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rawRequest issues a request with a verbatim Authorization header (empty
// header omitted), returning the response.
func rawRequest(t *testing.T, srv *httptest.Server, method, path, authHeader string, body []byte) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestAuthHeaderVariants rejects every malformed / wrong bearer token with 401.
func TestAuthHeaderVariants(t *testing.T) {
	srv, operatorKey := newTestServer(t)
	id := strings.Split(operatorKey, "_")[1]

	variants := []string{
		"",                              // no header
		"Bearer",                        // prefix only, no space/token
		"Bearer x",                      // not a mnemoca key
		"mnemoca_" + id + "_wrongsecret", // missing "Bearer " prefix
		"Bearer mnemoca_" + id + "_" + strings.Repeat("0", 64), // real id, wrong secret
		"Bearer mnemoca__",              // empty id and secret
	}
	for _, h := range variants {
		resp := rawRequest(t, srv, "GET", "/api/v1/tenants", h, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			t.Fatalf("auth header %q: status %d, want 401 (body: %s)", h, resp.StatusCode, body)
		}
		_ = resp.Body.Close()
	}
}

// TestMalformedRequestBodies rejects invalid JSON, unknown fields, and
// oversized bodies with 4xx (not 5xx).
func TestMalformedRequestBodies(t *testing.T) {
	srv, operatorKey := newTestServer(t)

	cases := map[string][]byte{
		"invalid-json":  []byte("{ this is not json"),
		"unknown-field": []byte(`{"id":"t1","totally_unknown":true}`),
		"oversized":     []byte(`{"id":"` + strings.Repeat("a", 2<<20) + `"}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp := rawRequest(t, srv, "POST", "/api/v1/tenants", "Bearer "+operatorKey, body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				data, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d, want 4xx (body: %s)", resp.StatusCode, data)
			}
		})
	}
}

// TestIssueGarbageCSR rejects an unparseable CSR with 400.
func TestIssueGarbageCSR(t *testing.T) {
	srv, operatorKey := newTestServer(t)
	call(t, srv, "POST", "/api/v1/tenants", operatorKey, map[string]any{"id": "t1"}, nil)

	resp := call(t, srv, "POST", "/api/v1/tenants/t1/issue", operatorKey,
		map[string]any{"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\ngarbage\n-----END CERTIFICATE REQUEST-----"}, nil)
	wantStatus(t, resp, http.StatusBadRequest)
}

// TestRevokeUnknownSerial returns a 4xx (not a 5xx) for an unknown serial.
func TestRevokeUnknownSerial(t *testing.T) {
	srv, operatorKey := newTestServer(t)
	call(t, srv, "POST", "/api/v1/tenants", operatorKey, map[string]any{"id": "t1"}, nil)

	resp := call(t, srv, "POST", "/api/v1/tenants/t1/revoke", operatorKey,
		map[string]any{"serial": "123456789", "reason_code": 1}, nil)
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("revoke unknown serial: status %d, want 4xx", resp.StatusCode)
	}
}

// TestCRLUnknownTenant returns 404 for a tenant that does not exist.
func TestCRLUnknownTenant(t *testing.T) {
	srv, _ := newTestServer(t)
	resp := call(t, srv, "GET", "/crl/no-such-tenant", "", nil, nil)
	wantStatus(t, resp, http.StatusNotFound)
}

// TestTenantScopedKeyBoundary confirms a tenant-scoped key is confined to its
// own tenant: it may issue there but cannot cross tenants, list all tenants,
// create tenants, or mint API keys.
func TestTenantScopedKeyBoundary(t *testing.T) {
	srv, operatorKey := newTestServer(t)
	call(t, srv, "POST", "/api/v1/tenants", operatorKey, map[string]any{"id": "t1"}, nil)
	call(t, srv, "POST", "/api/v1/tenants", operatorKey, map[string]any{"id": "t2"}, nil)

	var created struct {
		Key string `json:"key"`
	}
	resp := call(t, srv, "POST", "/api/v1/apikeys", operatorKey,
		map[string]any{"role": "tenant", "tenant": "t1"}, &created)
	wantStatus(t, resp, http.StatusCreated)
	tenantKey := created.Key

	// Allowed: issue in its own tenant.
	resp = call(t, srv, "POST", "/api/v1/tenants/t1/issue", tenantKey,
		map[string]any{"csr_pem": testCSRPEM(t, "own-tenant")}, nil)
	wantStatus(t, resp, http.StatusOK)

	// Forbidden: any action in a different tenant.
	resp = call(t, srv, "POST", "/api/v1/tenants/t2/issue", tenantKey,
		map[string]any{"csr_pem": testCSRPEM(t, "cross-tenant")}, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "POST", "/api/v1/tenants/t2/revoke", tenantKey,
		map[string]any{"serial": "1"}, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "GET", "/api/v1/tenants/t2/certificates", tenantKey, nil, nil)
	wantStatus(t, resp, http.StatusForbidden)

	// Forbidden: operator-only endpoints.
	resp = call(t, srv, "GET", "/api/v1/tenants", tenantKey, nil, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "POST", "/api/v1/tenants", tenantKey, map[string]any{"id": "t9"}, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "POST", "/api/v1/apikeys", tenantKey,
		map[string]any{"role": "tenant", "tenant": "t1"}, nil)
	wantStatus(t, resp, http.StatusForbidden)
}
