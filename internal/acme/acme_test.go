package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// testEnv opens an initialized CA env with tenant "t1".
func testEnv(t *testing.T) *ca.Env {
	t.Helper()
	env, err := ca.OpenEnv(t.TempDir(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Close() })
	actor := audit.Actor{Type: "operator", ID: "test"}
	if _, err := env.Init(context.Background(), ca.InitOptions{Alg: pkix.MLDSA65, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.CreateTenant(context.Background(), "t1", "", "", false, actor); err != nil {
		t.Fatal(err)
	}
	return env
}

// newACMEServer serves the ACME handler over a pre-bound listener so the
// ExternalURL is known before the handler is constructed.
func newACMEServer(t *testing.T, env *ca.Env, opts Options) (*httptest.Server, *server) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts.ExternalURL = "http://" + l.Addr().String()
	h := New(env.Manager, env.Store, env.Manager.Audit, opts)
	ts := httptest.NewUnstartedServer(h)
	_ = ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	t.Cleanup(ts.Close)
	return ts, h.(*server)
}

// testClient is a minimal ACME client with an ES256 account key.
type testClient struct {
	t   *testing.T
	key *ecdsa.PrivateKey
	kid string
	dir struct {
		NewNonce   string `json:"newNonce"`
		NewAccount string `json:"newAccount"`
		NewOrder   string `json:"newOrder"`
		RevokeCert string `json:"revokeCert"`
		Meta       struct {
			ExternalAccountRequired bool `json:"externalAccountRequired"`
		} `json:"meta"`
	}
}

func newTestClient(t *testing.T, baseURL string) *testClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &testClient{t: t, key: key}
	resp, err := http.Get(baseURL + "/acme/t1/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("directory status = %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&c.dir); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *testClient) jwkJSON() string {
	point, err := c.key.PublicKey.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil {
		c.t.Fatal(err)
	}
	return fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(point[1:33]), base64.RawURLEncoding.EncodeToString(point[33:65]))
}

func (c *testClient) nonce() string {
	c.t.Helper()
	req, err := http.NewRequest(http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	_ = resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		c.t.Fatal("new-nonce returned no Replay-Nonce header")
	}
	return n
}

// signBody builds a flattened JWS over payload ("" means POST-as-GET).
func (c *testClient) signBody(url, payload, nonce string, useJWK bool) []byte {
	c.t.Helper()
	prot := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
	if useJWK {
		prot["jwk"] = json.RawMessage(c.jwkJSON())
	} else {
		prot["kid"] = c.kid
	}
	pj, err := json.Marshal(prot)
	if err != nil {
		c.t.Fatal(err)
	}
	p64 := base64.RawURLEncoding.EncodeToString(pj)
	var pay64 string
	if payload != "" {
		pay64 = base64.RawURLEncoding.EncodeToString([]byte(payload))
	}
	sum := sha256.Sum256([]byte(p64 + "." + pay64))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, sum[:])
	if err != nil {
		c.t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	body, err := json.Marshal(map[string]string{
		"protected": p64,
		"payload":   pay64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		c.t.Fatal(err)
	}
	return body
}

func (c *testClient) postNonce(url, payload, nonce string, useJWK bool) (*http.Response, []byte) {
	c.t.Helper()
	resp, err := http.Post(url, "application/jose+json", bytes.NewReader(c.signBody(url, payload, nonce, useJWK)))
	if err != nil {
		c.t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		c.t.Fatal(err)
	}
	return resp, data
}

func (c *testClient) post(url, payload string, useJWK bool) (*http.Response, []byte) {
	c.t.Helper()
	return c.postNonce(url, payload, c.nonce(), useJWK)
}

func decodeProblem(t *testing.T, body []byte) problem {
	t.Helper()
	var p problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decoding problem %s: %v", body, err)
	}
	return p
}

// TestACMEFlow drives the full cert-manager-shaped flow: directory → nonce
// → newAccount → newOrder → http-01 → finalize → download → revoke.
func TestACMEFlow(t *testing.T) {
	env := testEnv(t)
	ts, srv := newACMEServer(t, env, Options{})

	// Challenge responder: serves token.thumbprint for any token.
	var mu sync.Mutex
	var thumb string
	chSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		mu.Lock()
		th := thumb
		mu.Unlock()
		_, _ = fmt.Fprintf(w, "%s.%s", token, th)
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

	// Unknown tenant → 404 problem+json.
	resp, err := http.Get(ts.URL + "/acme/nope/directory")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown tenant directory status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("unknown tenant content type = %q", ct)
	}

	c := newTestClient(t, ts.URL)
	if c.dir.Meta.ExternalAccountRequired {
		t.Fatal("externalAccountRequired should be false")
	}

	// newAccount.
	resp, body := c.post(c.dir.NewAccount, `{"termsOfServiceAgreed":true,"contact":["mailto:ops@example.com"]}`, true)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount status = %d: %s", resp.StatusCode, body)
	}
	c.kid = resp.Header.Get("Location")
	if !strings.Contains(c.kid, "/acme/t1/account/") {
		t.Fatalf("account Location = %q", c.kid)
	}
	th, err := jwkThumbprint([]byte(c.jwkJSON()))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	thumb = th
	mu.Unlock()

	// newAccount again with the same key returns the existing account.
	resp, body = c.post(c.dir.NewAccount, `{"onlyReturnExisting":true}`, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("existing account status = %d: %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != c.kid {
		t.Fatalf("existing account Location = %q, want %q", loc, c.kid)
	}

	// newOrder.
	resp, body = c.post(c.dir.NewOrder, `{"identifiers":[{"type":"dns","value":"localhost"}]}`, false)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d: %s", resp.StatusCode, body)
	}
	orderURL := resp.Header.Get("Location")
	var ord orderResp
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatal(err)
	}
	if ord.Status != "pending" || len(ord.Authorizations) != 1 || ord.Finalize == "" {
		t.Fatalf("order = %+v", ord)
	}

	// Authorization (POST-as-GET) → pick the http-01 challenge.
	resp, body = c.post(ord.Authorizations[0], "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authz status = %d: %s", resp.StatusCode, body)
	}
	var az authzResp
	if err := json.Unmarshal(body, &az); err != nil {
		t.Fatal(err)
	}
	if az.Identifier.Value != "localhost" || len(az.Challenges) != 2 {
		t.Fatalf("authz = %+v", az)
	}
	var httpChal challengeResp
	for _, ch := range az.Challenges {
		if ch.Type == "http-01" {
			httpChal = ch
		}
	}
	if httpChal.URL == "" || httpChal.Token == "" {
		t.Fatalf("no http-01 challenge in %+v", az.Challenges)
	}

	// Trigger validation.
	resp, body = c.post(httpChal.URL, "{}", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge status = %d: %s", resp.StatusCode, body)
	}
	var chResp challengeResp
	if err := json.Unmarshal(body, &chResp); err != nil {
		t.Fatal(err)
	}
	if chResp.Status != "valid" {
		t.Fatalf("challenge = %+v", chResp)
	}

	// Order is now ready.
	resp, body = c.post(orderURL, "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("order status = %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatal(err)
	}
	if ord.Status != "ready" {
		t.Fatalf("order status = %q, want ready", ord.Status)
	}

	// Finalize with an ECDSA CSR.
	leafKey, err := pkix.GenerateKey(pkix.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pkix.CreateCertificateRequest(&x509.CertificateRequest{
		DNSNames: []string{"localhost"},
	}, leafKey, pkix.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	resp, body = c.post(ord.Finalize, fmt.Sprintf(`{"csr":%q}`, base64.RawURLEncoding.EncodeToString(csr.Raw)), false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &ord); err != nil {
		t.Fatal(err)
	}
	if ord.Status != "valid" || ord.Certificate == "" {
		t.Fatalf("finalized order = %+v", ord)
	}

	// Download and verify the chain.
	resp, body = c.post(ord.Certificate, "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cert status = %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Fatalf("cert content type = %q", ct)
	}
	chain, err := pkix.ParseChainPEM(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("chain length = %d, want 3 (leaf, issuing, root)", len(chain))
	}
	if err := pkix.VerifyChain(chain, time.Now()); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if got := chain[0].X509.DNSNames; len(got) != 1 || got[0] != "localhost" {
		t.Fatalf("leaf DNS names = %v", got)
	}
	if chain[0].Algorithm != pkix.MLDSA65 {
		t.Fatalf("leaf signed with %q, want ml-dsa-65", chain[0].Algorithm)
	}

	// Revoke through the account that ordered it.
	serial := chain[0].X509.SerialNumber.String()
	revokePayload := fmt.Sprintf(`{"certificate":%q,"reason":1}`, base64.RawURLEncoding.EncodeToString(chain[0].Raw))
	resp, body = c.post(c.dir.RevokeCert, revokePayload, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status = %d: %s", resp.StatusCode, body)
	}
	rec, err := env.Manager.GetCertificate("t1", serial)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Revoked || rec.ReasonCode != 1 {
		t.Fatalf("cert record = %+v", rec)
	}

	// Double revocation → alreadyRevoked.
	resp, body = c.post(c.dir.RevokeCert, revokePayload, false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("re-revoke status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"alreadyRevoked" {
		t.Fatalf("re-revoke problem = %+v", p)
	}
}

// TestBadNonce checks that a stale/unknown nonce is rejected with badNonce
// and that the error response still carries a fresh Replay-Nonce.
func TestBadNonce(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{})
	c := newTestClient(t, ts.URL)

	resp, body := c.postNonce(c.dir.NewAccount, `{"termsOfServiceAgreed":true}`, "bogus-nonce", true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"badNonce" {
		t.Fatalf("problem = %+v", p)
	}
	if resp.Header.Get("Replay-Nonce") == "" {
		t.Fatal("badNonce response is missing a fresh Replay-Nonce")
	}

	// A nonce is single-use: replaying one is rejected.
	n := c.nonce()
	resp, body = c.postNonce(c.dir.NewAccount, `{"termsOfServiceAgreed":true}`, n, true)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first use status = %d: %s", resp.StatusCode, body)
	}
	resp, body = c.postNonce(c.dir.NewAccount, `{"termsOfServiceAgreed":true}`, n, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"badNonce" {
		t.Fatalf("replay problem = %+v", p)
	}
}

// TestEABRequired checks that RequireEAB rejects unbound registrations and
// accepts a correctly MAC'd externalAccountBinding.
func TestEABRequired(t *testing.T) {
	env := testEnv(t)
	ts, _ := newACMEServer(t, env, Options{RequireEAB: true})
	c := newTestClient(t, ts.URL)
	if !c.dir.Meta.ExternalAccountRequired {
		t.Fatal("directory meta should require external accounts")
	}

	resp, body := c.post(c.dir.NewAccount, `{"termsOfServiceAgreed":true}`, true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d: %s", resp.StatusCode, body)
	}
	if p := decodeProblem(t, body); p.Type != errURN+"externalAccountRequired" {
		t.Fatalf("problem = %+v", p)
	}

	kid, keyB64, err := CreateEABKey(env.Store, "t1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	p64 := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"alg":"HS256","kid":%q,"url":%q}`, kid, c.dir.NewAccount))
	pay64 := base64.RawURLEncoding.EncodeToString([]byte(c.jwkJSON()))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(p64 + "." + pay64))
	eab := fmt.Sprintf(`{"protected":%q,"payload":%q,"signature":%q}`,
		p64, pay64, base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))

	resp, body = c.post(c.dir.NewAccount, fmt.Sprintf(`{"termsOfServiceAgreed":true,"externalAccountBinding":%s}`, eab), true)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("EAB newAccount status = %d: %s", resp.StatusCode, body)
	}
}
