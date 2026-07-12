// Package api implements MnemoCA's JSON REST API (PLAN §2.5): tenant
// lifecycle, certificate issuance and revocation, CRL distribution, and API
// key administration over the CA engine. Authentication is bearer API keys
// (operator or tenant-scoped); the ACME handler is mounted under /acme/.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/mnemoshare/mnemoca/internal/ca"
)

// Options configures the API handler.
type Options struct {
	// ExternalURL is the base URL clients reach the server at (used by the
	// ACME handler for directory URLs).
	ExternalURL string
	// ACME, if non-nil, is mounted under /acme/.
	ACME http.Handler
}

type server struct {
	env  *ca.Env
	opts Options
}

// New builds the REST API handler over an opened CA environment. On first
// start (no API keys stored) it generates a bootstrap operator key and prints
// the plaintext once to stderr.
func New(env *ca.Env, opts Options) http.Handler {
	s := &server{env: env, opts: opts}
	if err := s.bootstrapKey(); err != nil {
		fmt.Fprintf(os.Stderr, "mnemoca: bootstrap API key: %v\n", err)
	}

	mux := http.NewServeMux()

	// Unauthenticated: health, trust anchors, revocation.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /roots", s.handleRoots)
	mux.HandleFunc("GET /crl/{tenant}", s.handleCRL(ca.ChainPrimary))
	mux.HandleFunc("GET /crl/{tenant}/pair", s.handleCRL(ca.ChainPair))
	if opts.ACME != nil {
		mux.Handle("/acme/", opts.ACME)
	}

	// Authenticated API.
	mux.HandleFunc("POST /api/v1/tenants", s.authed(s.operatorOnly(s.handleCreateTenant)))
	mux.HandleFunc("GET /api/v1/tenants", s.authed(s.operatorOnly(s.handleListTenants)))
	mux.HandleFunc("GET /api/v1/tenants/{id}", s.authed(s.tenantScoped(s.handleGetTenant)))
	mux.HandleFunc("POST /api/v1/tenants/{id}/issue", s.authed(s.tenantScoped(s.handleIssue)))
	mux.HandleFunc("POST /api/v1/tenants/{id}/revoke", s.authed(s.tenantScoped(s.handleRevoke)))
	mux.HandleFunc("GET /api/v1/tenants/{id}/certificates", s.authed(s.tenantScoped(s.handleListCertificates)))
	mux.HandleFunc("GET /api/v1/tenants/{id}/profiles", s.authed(s.tenantScoped(s.handleListProfiles)))
	mux.HandleFunc("PUT /api/v1/tenants/{id}/profiles/{name}", s.authed(s.tenantScoped(s.handleSetProfile)))
	mux.HandleFunc("DELETE /api/v1/tenants/{id}/profiles/{name}", s.authed(s.tenantScoped(s.handleDeleteProfile)))
	mux.HandleFunc("GET /api/v1/algorithms", s.authed(s.handleAlgorithms))
	mux.HandleFunc("POST /api/v1/apikeys", s.authed(s.operatorOnly(s.handleCreateAPIKey)))

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Headers are already out; nothing useful left to do.
		fmt.Fprintf(os.Stderr, "mnemoca: api: encoding response: %v\n", err)
	}
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, args...)})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}
