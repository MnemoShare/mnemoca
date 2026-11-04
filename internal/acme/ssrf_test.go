package acme

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestBlockedAddress(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.8.8.8", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"100.64.0.1", "100.127.255.254", "169.254.169.254", "169.254.0.5", "fe80::1", "fd00:ec2::254",
		"fc00::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"0.1.2.3", "240.0.0.1",
	}
	for _, a := range blocked {
		if !blockedAddress(net.ParseIP(a)) {
			t.Errorf("%s must be blocked", a)
		}
	}
	allowed := []string{"93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "100.63.255.255", "172.32.0.1"}
	for _, a := range allowed {
		if blockedAddress(net.ParseIP(a)) {
			t.Errorf("%s must be allowed", a)
		}
	}
}

func TestSafeDialControlRejectsResolvedAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:80", "[::1]:80", "169.254.169.254:80", "10.0.0.1:8080"} {
		if err := safeDialControl("tcp", addr, nil); err == nil {
			t.Errorf("%s accepted", addr)
		}
	}
	if err := safeDialControl("tcp", "93.184.216.34:80", nil); err != nil {
		t.Errorf("public address rejected: %v", err)
	}
}

func challengeServer(t *testing.T) (port int, hits *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		_, _ = fmt.Fprint(w, "tok.thumb")
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ = strconv.Atoi(u.Port())
	return port, &n
}

func TestHTTP01RefusesHostResolvingToLoopback(t *testing.T) {
	env := testEnv(t)
	port, hits := challengeServer(t)
	h := New(env.Manager, env.Store, env.Manager.Audit, Options{ExternalURL: "http://x"}).(*server)
	h.httpPort = port

	// "localhost" resolves to 127.0.0.1: the dialer must refuse after DNS.
	err := h.checkHTTP01(context.Background(), "localhost", "tok", "tok.thumb")
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("err = %v, want a not-permitted dial error", err)
	}
	// A literal IP is refused too.
	if err := h.checkHTTP01(context.Background(), "127.0.0.1", "tok", "tok.thumb"); err == nil {
		t.Fatal("literal loopback accepted")
	}
	if *hits != 0 {
		t.Fatalf("challenge server was contacted %d times", *hits)
	}
}

func TestHTTP01AllowPrivateOptIn(t *testing.T) {
	env := testEnv(t)
	port, hits := challengeServer(t)
	h := New(env.Manager, env.Store, env.Manager.Audit, Options{ExternalURL: "http://x", AllowPrivateAddresses: true}).(*server)
	h.httpPort = port
	if err := h.checkHTTP01(context.Background(), "localhost", "tok", "tok.thumb"); err != nil {
		t.Fatalf("opt-in lab mode failed: %v", err)
	}
	if *hits != 1 {
		t.Fatalf("hits = %d, want 1", *hits)
	}
}

func TestBlockedTransitionAddresses(t *testing.T) {
	for _, a := range []string{"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::1", "2002:7f00:1::1", "2002:a00:1::", "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"} {
		if !blockedAddress(net.ParseIP(a)) {
			t.Errorf("%s must be blocked", a)
		}
	}
}

func TestChallengeRedirectPolicy(t *testing.T) {
	mk := func(raw string) *http.Request {
		u, _ := url.Parse(raw)
		return &http.Request{URL: u}
	}
	for _, ok := range []string{"http://example.com/x", "https://example.com/x", "https://example.com:443/x", "http://example.com:80/x"} {
		if err := challengeRedirectPolicy(mk(ok), nil); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://example.com/x", "http://example.com:8080/x", "https://example.com:8443/x", "http://example.com:22/x", "gopher://example.com/"} {
		if err := challengeRedirectPolicy(mk(bad), nil); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	via := make([]*http.Request, maxChallengeRedirects)
	if err := challengeRedirectPolicy(mk("http://example.com/"), via); err == nil {
		t.Error("redirect limit not enforced")
	}
}

// redirectClient dials only the test server directly; every other address goes
// through the real guard.
func redirectClient(t *testing.T, srvAddr string) *http.Client {
	t.Helper()
	c := newChallengeClientWithControl(func(network, address string, rc syscall.RawConn) error {
		if address == srvAddr {
			return nil
		}
		return safeDialControl(network, address, rc)
	})
	return c
}

func TestChallengeRedirectsAreGuarded(t *testing.T) {
	var target string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	c := redirectClient(t, addr)

	for name, dest := range map[string]string{
		"private address": "http://10.0.0.5/secret",
		"metadata":        "http://169.254.169.254/latest/meta-data/",
		"odd port":        "http://93.184.216.34:8080/x",
		"loopback":        "http://127.0.0.1:1/x",
	} {
		target = dest
		resp, err := c.Get(srv.URL)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: redirect followed", name)
		}
	}
}
