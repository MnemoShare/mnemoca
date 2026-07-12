package api

import (
	"bytes"
	"context"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

var keyRe = regexp.MustCompile(`mnemoca_[0-9a-f]+_[0-9a-f]+`)

// newTestServer initializes a real CA env, builds the API handler (capturing
// the bootstrap operator key printed to stderr), and serves it via httptest.
func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	env, err := ca.OpenEnv(t.TempDir(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Close() })
	if _, err := env.Init(context.Background(), ca.InitOptions{
		Alg:   pkix.MLDSA65,
		Actor: audit.Actor{Type: "operator", ID: "test"},
	}); err != nil {
		t.Fatal(err)
	}

	// Capture stderr around New to harvest the bootstrap key.
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	handler := New(env, Options{})
	_ = w.Close()
	os.Stderr = old
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	bootstrapKey := keyRe.FindString(string(captured))
	if bootstrapKey == "" {
		t.Fatalf("no bootstrap key printed to stderr; got: %q", captured)
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, bootstrapKey
}

// call performs an HTTP request with an optional bearer key and JSON body,
// decoding a JSON response into out (when out is non-nil).
func call(t *testing.T, srv *httptest.Server, method, path, bearer string, body, out any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("%s %s: decoding response %q: %v", method, path, data, err)
		}
	}
	return resp
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s: status %d, want %d (body: %s)",
			resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, body)
	}
}

func testCSRPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := pkix.GenerateKey(pkix.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pkix.CreateCertificateRequest(&x509.CertificateRequest{
		Subject:  stdpkix.Name{CommonName: cn},
		DNSNames: []string{cn + ".example.com"},
	}, key, pkix.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return string(pkix.EncodeCSRPEM(csr))
}

func TestAPI(t *testing.T) {
	srv, operatorKey := newTestServer(t)

	// Health and roots need no auth.
	resp := call(t, srv, "GET", "/healthz", "", nil, nil)
	wantStatus(t, resp, http.StatusOK)

	resp = call(t, srv, "GET", "/roots", "", nil, nil)
	wantStatus(t, resp, http.StatusOK)
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-pem-file" {
		t.Fatalf("roots content-type = %q", ct)
	}
	rootsPEM, _ := io.ReadAll(resp.Body)
	if _, err := pkix.ParseChainPEM(rootsPEM); err != nil {
		t.Fatalf("roots bundle: %v", err)
	}

	// Bad bearer tokens are rejected.
	for _, bearer := range []string{"", "garbage", "mnemoca_deadbeef_deadbeef"} {
		resp = call(t, srv, "GET", "/api/v1/tenants", bearer, nil, nil)
		wantStatus(t, resp, http.StatusUnauthorized)
	}
	// Wrong secret for a real key ID is rejected too.
	id := strings.Split(operatorKey, "_")[1]
	resp = call(t, srv, "GET", "/api/v1/tenants", "mnemoca_"+id+"_"+strings.Repeat("0", 64), nil, nil)
	wantStatus(t, resp, http.StatusUnauthorized)

	// Create two tenants with the bootstrap operator key.
	var tenant struct {
		ID      string `json:"id"`
		CertPEM string `json:"cert_pem"`
	}
	resp = call(t, srv, "POST", "/api/v1/tenants", operatorKey,
		map[string]any{"id": "t1", "name": "Tenant One"}, &tenant)
	wantStatus(t, resp, http.StatusCreated)
	if tenant.ID != "t1" || !strings.Contains(tenant.CertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("tenant response = %+v", tenant)
	}
	resp = call(t, srv, "POST", "/api/v1/tenants", operatorKey, map[string]any{"id": "t2"}, nil)
	wantStatus(t, resp, http.StatusCreated)

	var list struct {
		Tenants []struct {
			ID string `json:"id"`
		} `json:"tenants"`
	}
	resp = call(t, srv, "GET", "/api/v1/tenants", operatorKey, nil, &list)
	wantStatus(t, resp, http.StatusOK)
	if len(list.Tenants) != 2 {
		t.Fatalf("tenant list = %+v", list)
	}

	// Issue from an ECDSA CSR.
	var issued struct {
		Certificates []struct {
			Chain    string    `json:"chain"`
			CertPEM  string    `json:"cert_pem"`
			ChainPEM string    `json:"chain_pem"`
			Serial   string    `json:"serial"`
			NotAfter time.Time `json:"not_after"`
		} `json:"certificates"`
	}
	resp = call(t, srv, "POST", "/api/v1/tenants/t1/issue", operatorKey,
		map[string]any{"csr_pem": testCSRPEM(t, "client-a"), "validity": "24h"}, &issued)
	wantStatus(t, resp, http.StatusOK)
	if len(issued.Certificates) != 1 {
		t.Fatalf("issued = %+v", issued)
	}
	got := issued.Certificates[0]
	if got.Chain != "primary" || got.Serial == "" {
		t.Fatalf("issued cert = %+v", got)
	}
	leaf, err := pkix.ParseCertificatePEM([]byte(got.CertPEM))
	if err != nil {
		t.Fatalf("leaf PEM: %v", err)
	}
	if leaf.Algorithm != pkix.MLDSA65 {
		t.Fatalf("leaf signed with %q, want ml-dsa-65", leaf.Algorithm)
	}
	chain, err := pkix.ParseChainPEM([]byte(got.ChainPEM))
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3 (leaf, issuing, root)", len(chain))
	}
	if err := pkix.VerifyChain(chain, time.Now()); err != nil {
		t.Fatalf("chain: %v", err)
	}

	// List certificates: record present, PEM omitted.
	resp = call(t, srv, "GET", "/api/v1/tenants/t1/certificates", operatorKey, nil, nil)
	wantStatus(t, resp, http.StatusOK)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), got.Serial) {
		t.Fatalf("certificates list missing serial: %s", body)
	}
	if strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("certificates list leaks PEM: %s", body)
	}

	// Revoke, then the CRL must carry the serial.
	resp = call(t, srv, "POST", "/api/v1/tenants/t1/revoke", operatorKey,
		map[string]any{"serial": got.Serial, "reason_code": 1}, nil)
	wantStatus(t, resp, http.StatusOK)

	resp = call(t, srv, "GET", "/crl/t1", "", nil, nil)
	wantStatus(t, resp, http.StatusOK)
	if ct := resp.Header.Get("Content-Type"); ct != "application/pkix-crl" {
		t.Fatalf("crl content-type = %q", ct)
	}
	der, _ := io.ReadAll(resp.Body)
	crl, err := pkix.ParseCRL(der)
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	if len(crl.Revoked) != 1 || crl.Revoked[0].SerialNumber.String() != got.Serial {
		t.Fatalf("CRL revoked = %+v", crl.Revoked)
	}
	resp = call(t, srv, "GET", "/crl/no-such-tenant", "", nil, nil)
	wantStatus(t, resp, http.StatusNotFound)

	// Algorithms listing includes flags.
	var algs struct {
		Algorithms []struct {
			Alg          string `json:"alg"`
			PQ           bool   `json:"pq"`
			Experimental bool   `json:"experimental"`
		} `json:"algorithms"`
	}
	resp = call(t, srv, "GET", "/api/v1/algorithms", operatorKey, nil, &algs)
	wantStatus(t, resp, http.StatusOK)
	if len(algs.Algorithms) != len(pkix.Algorithms()) {
		t.Fatalf("algorithms = %+v", algs)
	}

	// Tenant-scoped key: works on its tenant, forbidden elsewhere.
	var created struct {
		Key string `json:"key"`
	}
	resp = call(t, srv, "POST", "/api/v1/apikeys", operatorKey,
		map[string]any{"role": "tenant", "tenant": "t1"}, &created)
	wantStatus(t, resp, http.StatusCreated)
	if !keyRe.MatchString(created.Key) {
		t.Fatalf("apikey = %q", created.Key)
	}

	resp = call(t, srv, "GET", "/api/v1/tenants/t1", created.Key, nil, nil)
	wantStatus(t, resp, http.StatusOK)
	resp = call(t, srv, "POST", "/api/v1/tenants/t1/issue", created.Key,
		map[string]any{"csr_pem": testCSRPEM(t, "client-b")}, nil)
	wantStatus(t, resp, http.StatusOK)

	resp = call(t, srv, "GET", "/api/v1/tenants/t2", created.Key, nil, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "POST", "/api/v1/tenants/t2/issue", created.Key,
		map[string]any{"csr_pem": testCSRPEM(t, "client-c")}, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "GET", "/api/v1/tenants/t2/certificates", created.Key, nil, nil)
	wantStatus(t, resp, http.StatusForbidden)

	// Tenant keys cannot use operator-only endpoints.
	resp = call(t, srv, "GET", "/api/v1/tenants", created.Key, nil, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "POST", "/api/v1/tenants", created.Key, map[string]any{"id": "t3"}, nil)
	wantStatus(t, resp, http.StatusForbidden)
	resp = call(t, srv, "POST", "/api/v1/apikeys", created.Key,
		map[string]any{"role": "operator"}, nil)
	wantStatus(t, resp, http.StatusForbidden)
}

// TestBootstrapOnce verifies the bootstrap key is only generated when no keys
// exist.
func TestBootstrapOnce(t *testing.T) {
	env, err := ca.OpenEnv(t.TempDir(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Close() })
	if _, err := env.Init(context.Background(), ca.InitOptions{
		Alg:   pkix.MLDSA65,
		Actor: audit.Actor{Type: "operator", ID: "test"},
	}); err != nil {
		t.Fatal(err)
	}

	capture := func() string {
		old := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stderr = w
		New(env, Options{})
		_ = w.Close()
		os.Stderr = old
		data, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	if first := capture(); !keyRe.MatchString(first) {
		t.Fatalf("first start printed no bootstrap key: %q", first)
	}
	if second := capture(); keyRe.MatchString(second) {
		t.Fatalf("second start printed another bootstrap key: %q", second)
	}
}

// TestACMEMount verifies a provided ACME handler is reachable under /acme/.
func TestACMEMount(t *testing.T) {
	env, err := ca.OpenEnv(t.TempDir(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Close() })
	if _, err := env.Init(context.Background(), ca.InitOptions{
		Alg:   pkix.MLDSA65,
		Actor: audit.Actor{Type: "operator", ID: "test"},
	}); err != nil {
		t.Fatal(err)
	}

	old := os.Stderr
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = devnull
	handler := New(env, Options{ACME: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "acme:%s", r.URL.Path)
	})})
	os.Stderr = old
	_ = devnull.Close()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL + "/acme/t1/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "acme:/acme/t1/directory" {
		t.Fatalf("acme mount response = %q", body)
	}
}
