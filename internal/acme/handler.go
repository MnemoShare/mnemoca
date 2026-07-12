package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// Options configures the ACME handler.
type Options struct {
	ExternalURL string // e.g. "https://ca.example.com" — used in all returned URLs
	RequireEAB  bool
}

// server implements the ADR-0007 RFC 8555 subset over the CA engine. It
// never touches signing keys: issuance goes through ca.Manager like every
// other client.
type server struct {
	mgr  *ca.Manager
	st   *store.Store
	log  audit.Logger
	opts Options
	mux  *http.ServeMux

	// Test seams for challenge validation.
	httpPort   int           // http-01 target port (default 80)
	resolver   *net.Resolver // dns-01 TXT lookups
	httpClient *http.Client  // http-01 fetches
}

// New returns the ACME handler. It is mounted at "/" and owns all paths
// under /acme/.
func New(mgr *ca.Manager, st *store.Store, log audit.Logger, opts Options) http.Handler {
	opts.ExternalURL = strings.TrimRight(opts.ExternalURL, "/")
	s := &server{
		mgr:        mgr,
		st:         st,
		log:        log,
		opts:       opts,
		httpPort:   80,
		resolver:   net.DefaultResolver,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /acme/{tenant}/directory", s.withTenant(s.handleDirectory))
	mux.HandleFunc("HEAD /acme/{tenant}/new-nonce", s.withTenant(s.handleNewNonceHead))
	mux.HandleFunc("GET /acme/{tenant}/new-nonce", s.withTenant(s.handleNewNonceGet))
	mux.HandleFunc("POST /acme/{tenant}/new-account", s.post(true, s.handleNewAccount))
	mux.HandleFunc("POST /acme/{tenant}/account/{id}", s.post(false, s.handleAccount))
	mux.HandleFunc("POST /acme/{tenant}/new-order", s.post(false, s.handleNewOrder))
	mux.HandleFunc("POST /acme/{tenant}/order/{id}", s.post(false, s.handleOrder))
	mux.HandleFunc("POST /acme/{tenant}/order/{id}/finalize", s.post(false, s.handleFinalize))
	mux.HandleFunc("POST /acme/{tenant}/authz/{id}", s.post(false, s.handleAuthz))
	mux.HandleFunc("POST /acme/{tenant}/chall/{id}", s.post(false, s.handleChallenge))
	mux.HandleFunc("POST /acme/{tenant}/cert/{id}", s.post(false, s.handleCert))
	mux.HandleFunc("POST /acme/{tenant}/revoke-cert", s.post(true, s.handleRevoke))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, errf(http.StatusNotFound, "malformed", "no such resource: %s", r.URL.Path))
	})
	s.mux = mux
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// url builds an external URL under the tenant's ACME prefix.
func (s *server) url(tenant, suffix string) string {
	return s.opts.ExternalURL + "/acme/" + tenant + suffix
}

// requestURL reconstructs the external URL of the incoming request; JWS
// protected headers must match it exactly (RFC 8555 §6.4).
func (s *server) requestURL(r *http.Request) string {
	return s.opts.ExternalURL + r.URL.Path
}

// checkTenant resolves the {tenant} path value against the CA engine.
func (s *server) checkTenant(r *http.Request) (string, error) {
	tenant := r.PathValue("tenant")
	if _, err := s.mgr.GetTenant(tenant); err != nil {
		return "", errf(http.StatusNotFound, "malformed", "unknown tenant %q", tenant)
	}
	return tenant, nil
}

// withTenant wraps GET/HEAD handlers with tenant resolution.
func (s *server) withTenant(fn func(w http.ResponseWriter, r *http.Request, tenant string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.checkTenant(r)
		if err != nil {
			writeError(w, err)
			return
		}
		fn(w, r, tenant)
	}
}

// post wraps ACME POST handlers: tenant resolution, Replay-Nonce issuance,
// and JWS verification (including single-use nonce consumption). allowJWK
// permits bare-jwk authentication (new-account and revoke-cert only).
func (s *server) post(allowJWK bool, fn func(w http.ResponseWriter, r *http.Request, req *jwsRequest) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.checkTenant(r)
		if err != nil {
			writeError(w, err)
			return
		}
		// Every POST response carries a fresh nonce, including errors, so
		// clients can retry badNonce failures (RFC 8555 §6.5).
		if err := s.issueNonce(w, tenant); err != nil {
			writeError(w, err)
			return
		}
		req, err := s.verifyRequest(r, tenant, allowJWK)
		if err != nil {
			writeError(w, err)
			return
		}
		if err := fn(w, r, req); err != nil {
			writeError(w, err)
		}
	}
}

// handleDirectory serves the tenant's directory object (RFC 8555 §7.1.1).
func (s *server) handleDirectory(w http.ResponseWriter, _ *http.Request, tenant string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   s.url(tenant, "/new-nonce"),
		"newAccount": s.url(tenant, "/new-account"),
		"newOrder":   s.url(tenant, "/new-order"),
		"revokeCert": s.url(tenant, "/revoke-cert"),
		"meta": map[string]any{
			"externalAccountRequired": s.opts.RequireEAB,
		},
	})
}

func (s *server) handleNewNonceHead(w http.ResponseWriter, _ *http.Request, tenant string) {
	if err := s.issueNonce(w, tenant); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleNewNonceGet(w http.ResponseWriter, _ *http.Request, tenant string) {
	if err := s.issueNonce(w, tenant); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// audit appends one ACME audit record via the shared logger (ADR-0008).
func (s *server) audit(r *http.Request, tenant, action string, acctID string, obj audit.Object, detail map[string]string) error {
	actor := audit.Actor{Type: "acme", ID: acctID}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actor.IP = host
	}
	if err := s.log.Log(r.Context(), audit.Record{
		Tenant: tenant,
		Actor:  actor,
		Action: action,
		Object: obj,
		Detail: detail,
	}); err != nil {
		return fmt.Errorf("acme: audit append failed: %w", err)
	}
	return nil
}

// writeJSON writes v as an application/json response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		writeError(w, fmt.Errorf("acme: encoding response: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// writeError renders err as an ACME problem document; non-acmeErrors become
// serverInternal.
func writeError(w http.ResponseWriter, err error) {
	ae := &acmeError{status: http.StatusInternalServerError, code: "serverInternal", detail: err.Error()}
	var known *acmeError
	if errors.As(err, &known) {
		ae = known
	}
	data, mErr := json.Marshal(problem{Type: errURN + ae.code, Detail: ae.detail, Status: ae.status})
	if mErr != nil {
		http.Error(w, ae.detail, ae.status)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(ae.status)
	_, _ = w.Write(data)
}
