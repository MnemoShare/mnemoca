package acme

// Adversarial / negative-path coverage for the ACME server. Every case asserts
// a rejecting outcome (problem+json error, wrong-status, or unchanged state).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// registerAccount registers c's key as a new account and records its kid.
func registerAccount(t *testing.T, c *testClient) {
	t.Helper()
	resp, body := c.post(c.dir.NewAccount, `{"termsOfServiceAgreed":true}`, true)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount status = %d: %s", resp.StatusCode, body)
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		t.Fatal("newAccount returned no Location")
	}
}

// makeLeafCSR builds an ECDSA CSR requesting the given DNS names.
func makeLeafCSR(t *testing.T, dnsNames []string) *pkix.CertificateRequest {
	t.Helper()
	key, err := pkix.GenerateKey(pkix.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pkix.CreateCertificateRequest(&x509.CertificateRequest{DNSNames: dnsNames}, key, pkix.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// driveOrder creates an order for names, points http-01 validation at a local
// responder, and (for correct==true) drives it to "ready". For correct==false
// the responder serves a wrong key authorization, so validation fails.
func driveOrder(t *testing.T, srv *server, c *testClient, names []string, correct bool) (orderResp, string) {
	t.Helper()
	th, err := jwkThumbprint([]byte(c.jwkJSON()))
	if err != nil {
		t.Fatal(err)
	}
	chSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if correct {
			_, _ = fmt.Fprintf(w, "%s.%s", token, th)
		} else {
			_, _ = fmt.Fprintf(w, "%s.%s", token, "not-the-real-thumbprint")
		}
	}))
	t.Cleanup(chSrv.Close)
	chURL, err := url.Parse(chSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv.httpPort, err = strconv.Atoi(chURL.Port())
	if err != nil {
		t.Fatal(err)
	}

	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf(`{"type":"dns","value":%q}`, n)
	}
	payload := fmt.Sprintf(`{"identifiers":[%s]}`, strings.Join(parts, ","))

	resp, body := c.post(c.dir.NewOrder, payload, false)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d: %s", resp.StatusCode, body)
	}
	orderURL := resp.Header.Get("Location")
	var ord orderResp
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatal(err)
	}

	// Trigger the http-01 challenge in every authorization.
	for _, azURL := range ord.Authorizations {
		_, azBody := c.post(azURL, "", false)
		var az authzResp
		if err := json.Unmarshal(azBody, &az); err != nil {
			t.Fatal(err)
		}
		for _, ch := range az.Challenges {
			if ch.Type == "http-01" {
				c.post(ch.URL, "{}", false)
			}
		}
	}

	// Re-read the order to observe its resulting status.
	_, body = c.post(orderURL, "", false)
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatal(err)
	}
	return ord, orderURL
}

// TestJWSSignedByWrongKey rejects a request whose kid names a valid account but
// whose signature was made by a different key.
func TestJWSSignedByWrongKey(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)
	registerAccount(t, c)

	// Impostor client (fresh key, no account) reuses c's kid.
	impostor := newTestClient(t, ts.URL)
	impostor.kid = c.kid

	resp, body := impostor.post(c.dir.NewOrder, `{"identifiers":[{"type":"dns","value":"localhost"}]}`, false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"unauthorized" {
		t.Fatalf("problem = %+v", p)
	}
}

// TestKIDForAnotherAccount rejects signing with one's own key while pointing
// kid at a different account's URL.
func TestKIDForAnotherAccount(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{})

	a := newTestClient(t, ts.URL)
	registerAccount(t, a)
	b := newTestClient(t, ts.URL)
	registerAccount(t, b)

	// a signs with its own key but claims b's account URL.
	a.kid = b.kid
	resp, body := a.post(a.dir.NewOrder, `{"identifiers":[{"type":"dns","value":"localhost"}]}`, false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"unauthorized" {
		t.Fatalf("problem = %+v", p)
	}
}

// TestProtectedURLMismatch rejects a JWS whose protected "url" does not match
// the request target (RFC 8555 §6.4).
func TestProtectedURLMismatch(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)
	registerAccount(t, c)

	// Build a JWS whose protected header url points elsewhere, but POST it to
	// the real new-order endpoint.
	prot := map[string]any{
		"alg":   "ES256",
		"nonce": c.nonce(),
		"url":   ts.URL + "/acme/t1/some-other-url",
		"kid":   c.kid,
	}
	pj, err := json.Marshal(prot)
	if err != nil {
		t.Fatal(err)
	}
	p64 := base64.RawURLEncoding.EncodeToString(pj)
	pay64 := base64.RawURLEncoding.EncodeToString([]byte(`{"identifiers":[{"type":"dns","value":"localhost"}]}`))
	signed := signES256(t, c.key, p64, pay64)
	body, err := json.Marshal(map[string]string{"protected": p64, "payload": pay64, "signature": signed})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(c.dir.NewOrder, "application/jose+json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	data := readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d: %s", resp.StatusCode, data)
	}
	if p := decodeProblem(t, data); p.Type != errURN+"unauthorized" {
		t.Fatalf("problem = %+v", p)
	}
}

// TestNonceReplay rejects reuse of a single-use nonce across two requests.
func TestNonceReplay(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)
	registerAccount(t, c)

	n := c.nonce()
	payload := `{"identifiers":[{"type":"dns","value":"localhost"}]}`
	resp, body := c.postNonce(c.dir.NewOrder, payload, n, false)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first use status = %d: %s", resp.StatusCode, body)
	}
	resp, body = c.postNonce(c.dir.NewOrder, payload, n, false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"badNonce" {
		t.Fatalf("replay problem = %+v", p)
	}
}

// TestNewOrderIPIdentifier rejects an ip identifier type with a problem+json.
func TestNewOrderIPIdentifier(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)
	registerAccount(t, c)

	resp, body := c.post(c.dir.NewOrder, `{"identifiers":[{"type":"ip","value":"10.0.0.1"}]}`, false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type = %q", ct)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"unsupportedIdentifier" {
		t.Fatalf("problem = %+v", p)
	}
}

// TestFinalizeCSRNameMismatch rejects finalize CSRs whose DNS names do not
// exactly match the order identifiers (extra name and missing name).
func TestFinalizeCSRNameMismatch(t *testing.T) {
	env := testEnv(t)
	ts, srv := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)
	registerAccount(t, c)

	ord, _ := driveOrder(t, srv, c, []string{"localhost"}, true)
	if ord.Status != "ready" {
		t.Fatalf("order status = %q, want ready", ord.Status)
	}

	// Extra name the order never authorized.
	extra := makeLeafCSR(t, []string{"localhost", "extra.example.com"})
	resp, body := c.post(ord.Finalize, fmt.Sprintf(`{"csr":%q}`, b64(extra.Raw)), false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("extra-name status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"badCSR" {
		t.Fatalf("extra-name problem = %+v", p)
	}

	// Missing the order's only identifier (CSR has no DNS names).
	missing := makeLeafCSR(t, nil)
	resp, body = c.post(ord.Finalize, fmt.Sprintf(`{"csr":%q}`, b64(missing.Raw)), false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing-name status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"badCSR" {
		t.Fatalf("missing-name problem = %+v", p)
	}
}

// TestFinalizeBeforeReady rejects finalize on a pending order (challenges not
// yet validated) with orderNotReady.
func TestFinalizeBeforeReady(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)
	registerAccount(t, c)

	resp, body := c.post(c.dir.NewOrder, `{"identifiers":[{"type":"dns","value":"localhost"}]}`, false)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d: %s", resp.StatusCode, body)
	}
	var ord orderResp
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatal(err)
	}

	csr := makeLeafCSR(t, []string{"localhost"})
	resp, body = c.post(ord.Finalize, fmt.Sprintf(`{"csr":%q}`, b64(csr.Raw)), false)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("finalize-before-ready status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"orderNotReady" {
		t.Fatalf("problem = %+v", p)
	}
}

// TestChallengeWrongKeyAuthFails drives an http-01 challenge whose responder
// serves the wrong key authorization: the challenge and order go invalid and
// finalize is refused.
func TestChallengeWrongKeyAuthFails(t *testing.T) {
	env := testEnv(t)
	ts, srv := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)
	registerAccount(t, c)

	ord, _ := driveOrder(t, srv, c, []string{"localhost"}, false)
	if ord.Status == "ready" || ord.Status == "valid" {
		t.Fatalf("order reached %q despite a failed challenge", ord.Status)
	}

	csr := makeLeafCSR(t, []string{"localhost"})
	resp, body := c.post(ord.Finalize, fmt.Sprintf(`{"csr":%q}`, b64(csr.Raw)), false)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("finalize succeeded on an unvalidated order: %s", body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"orderNotReady" {
		t.Fatalf("problem = %+v", p)
	}
}

// TestCertDownloadWrongAccount rejects a certificate download by an account
// that did not order it.
func TestCertDownloadWrongAccount(t *testing.T) {
	env := testEnv(t)
	ts, srv := newACMEServer(t, env, Options{})

	owner := newTestClient(t, ts.URL)
	registerAccount(t, owner)
	ord, _ := driveOrder(t, srv, owner, []string{"localhost"}, true)
	if ord.Status != "ready" {
		t.Fatalf("order status = %q, want ready", ord.Status)
	}
	csr := makeLeafCSR(t, []string{"localhost"})
	resp, body := owner.post(ord.Finalize, fmt.Sprintf(`{"csr":%q}`, b64(csr.Raw)), false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatal(err)
	}
	if ord.Certificate == "" {
		t.Fatalf("finalized order has no certificate URL: %+v", ord)
	}

	// A different account on the same tenant must not download it.
	intruder := newTestClient(t, ts.URL)
	registerAccount(t, intruder)
	resp, body = intruder.post(ord.Certificate, "", false)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-account cert download status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"unauthorized" {
		t.Fatalf("problem = %+v", p)
	}
}

// signES256 signs the JWS signing input (p64.pay64) with an ES256 key and
// returns the base64url-encoded 64-byte signature.
func signES256(t *testing.T, key *ecdsa.PrivateKey, p64, pay64 string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(p64 + "." + pay64))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// readBody reads and closes an HTTP response body.
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
