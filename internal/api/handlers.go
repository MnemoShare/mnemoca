package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRoots serves the root certificate(s) as a PEM bundle (trust anchor
// distribution; both roots for hybrid instances).
func (s *server) handleRoots(w http.ResponseWriter, _ *http.Request) {
	root, err := s.env.Manager.Root()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "%v", err)
		return
	}
	bundle := append([]byte{}, root.CertPEM...)
	bundle = append(bundle, root.PairCertPEM...)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

// handleCRL builds and serves a fresh DER CRL for the tenant's chain.
func (s *server) handleCRL(chain ca.Chain) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant := r.PathValue("tenant")
		if _, err := s.env.Manager.GetTenant(tenant); err != nil {
			writeError(w, http.StatusNotFound, "%v", err)
			return
		}
		crl, err := s.env.Manager.BuildCRL(r.Context(), tenant, chain,
			audit.Actor{Type: "system", ID: "crl-endpoint", IP: r.RemoteAddr})
		if err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crl.Raw)
	}
}

// tenantJSON is the API view of a tenant (key references stay internal).
type tenantJSON struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	CreatedAt   time.Time      `json:"created_at"`
	Alg         pkix.Algorithm `json:"alg"`
	CertPEM     string         `json:"cert_pem"`
	PairAlg     pkix.Algorithm `json:"pair_alg,omitempty"`
	PairCertPEM string         `json:"pair_cert_pem,omitempty"`
}

func tenantView(t *ca.Tenant) tenantJSON {
	return tenantJSON{
		ID:          t.ID,
		Name:        t.Name,
		CreatedAt:   t.CreatedAt,
		Alg:         t.Alg,
		CertPEM:     string(t.CertPEM),
		PairAlg:     t.PairAlg,
		PairCertPEM: string(t.PairCertPEM),
	}
}

func (s *server) handleCreateTenant(w http.ResponseWriter, r *http.Request, key *apiKey) {
	var req struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Alg    string `json:"alg"`
		Hybrid bool   `json:"hybrid"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	t, err := s.env.Manager.CreateTenant(r.Context(), req.ID, req.Name, pkix.Algorithm(req.Alg), req.Hybrid, s.actor(key, r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, tenantView(t))
}

func (s *server) handleListTenants(w http.ResponseWriter, _ *http.Request, _ *apiKey) {
	tenants, err := s.env.Manager.ListTenants()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := make([]tenantJSON, 0, len(tenants))
	for i := range tenants {
		out = append(out, tenantView(&tenants[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

func (s *server) handleGetTenant(w http.ResponseWriter, r *http.Request, _ *apiKey) {
	t, err := s.env.Manager.GetTenant(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, tenantView(t))
}

// issuedJSON is one issued certificate in an issue response.
type issuedJSON struct {
	Chain    ca.Chain  `json:"chain"`
	CertPEM  string    `json:"cert_pem"`
	ChainPEM string    `json:"chain_pem"` // leaf + issuing CA + root
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
}

func (s *server) handleIssue(w http.ResponseWriter, r *http.Request, key *apiKey) {
	var req struct {
		CSRPEM                string `json:"csr_pem"`
		Profile               string `json:"profile"`
		Validity              string `json:"validity"`
		Chain                 string `json:"chain"`
		ExperimentalComposite bool   `json:"experimental_composite"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	csr, err := pkix.ParseCSRPEM([]byte(req.CSRPEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	var validity time.Duration
	if req.Validity != "" {
		validity, err = time.ParseDuration(req.Validity)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid validity: %v", err)
			return
		}
	}
	issued, err := s.env.Manager.Issue(r.Context(), ca.IssueRequest{
		Tenant:                r.PathValue("id"),
		Profile:               req.Profile,
		CSR:                   csr,
		Validity:              validity,
		Chain:                 ca.Chain(req.Chain),
		ExperimentalComposite: req.ExperimentalComposite,
		Actor:                 s.actor(key, r),
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	out := make([]issuedJSON, 0, len(issued))
	for _, iss := range issued {
		out = append(out, issuedJSON{
			Chain:    iss.Chain,
			CertPEM:  string(pkix.EncodeCertificatePEM(iss.Cert)),
			ChainPEM: string(pkix.EncodeChainPEM(iss.Path)),
			Serial:   iss.Cert.X509.SerialNumber.String(),
			NotAfter: iss.Cert.X509.NotAfter,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request, key *apiKey) {
	var req struct {
		Serial     string `json:"serial"`
		ReasonCode int    `json:"reason_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if err := s.env.Manager.Revoke(r.Context(), r.PathValue("id"), req.Serial, req.ReasonCode, s.actor(key, r)); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "serial": req.Serial})
}

// certJSON is the list view of an issued certificate; the PEM is omitted to
// keep list responses small.
type certJSON struct {
	Serial     string         `json:"serial"`
	Profile    string         `json:"profile"`
	Chain      ca.Chain       `json:"chain"`
	SubjectCN  string         `json:"subject_cn"`
	SANs       []string       `json:"sans,omitempty"`
	KeyAlg     pkix.Algorithm `json:"key_alg"`
	SigAlg     pkix.Algorithm `json:"sig_alg"`
	NotBefore  time.Time      `json:"not_before"`
	NotAfter   time.Time      `json:"not_after"`
	Revoked    bool           `json:"revoked"`
	RevokedAt  *time.Time     `json:"revoked_at,omitempty"`
	ReasonCode int            `json:"reason_code,omitempty"`
}

func (s *server) handleListCertificates(w http.ResponseWriter, r *http.Request, _ *apiKey) {
	recs, err := s.env.Manager.ListCertificates(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "%v", err)
		return
	}
	out := make([]certJSON, 0, len(recs))
	for _, rec := range recs {
		c := certJSON{
			Serial:     rec.Serial,
			Profile:    rec.Profile,
			Chain:      rec.Chain,
			SubjectCN:  rec.SubjectCN,
			SANs:       rec.SANs,
			KeyAlg:     rec.KeyAlg,
			SigAlg:     rec.SigAlg,
			NotBefore:  rec.NotBefore,
			NotAfter:   rec.NotAfter,
			Revoked:    rec.Revoked,
			ReasonCode: rec.ReasonCode,
		}
		if rec.Revoked {
			t := rec.RevokedAt
			c.RevokedAt = &t
		}
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
}

// algorithmJSON is one registry entry in the algorithms listing.
type algorithmJSON struct {
	Alg          pkix.Algorithm `json:"alg"`
	PQ           bool           `json:"pq"`
	Hybrid       bool           `json:"hybrid"`
	Experimental bool           `json:"experimental"`
}

func (s *server) handleAlgorithms(w http.ResponseWriter, _ *http.Request, _ *apiKey) {
	algs := pkix.Algorithms()
	slices.Sort(algs)
	out := make([]algorithmJSON, 0, len(algs))
	for _, alg := range algs {
		info, err := pkix.Lookup(alg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "%v", err)
			return
		}
		out = append(out, algorithmJSON{
			Alg:          info.Alg,
			PQ:           info.PQ,
			Hybrid:       info.Hybrid,
			Experimental: info.Experimental,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"algorithms": out})
}

func (s *server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request, key *apiKey) {
	var req struct {
		Role   string `json:"role"`
		Tenant string `json:"tenant"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	switch req.Role {
	case roleOperator:
		if req.Tenant != "" {
			writeError(w, http.StatusBadRequest, "operator keys must not be tenant-scoped")
			return
		}
	case roleTenant:
		if req.Tenant == "" {
			writeError(w, http.StatusBadRequest, "tenant-role keys require a tenant")
			return
		}
		if _, err := s.env.Manager.GetTenant(req.Tenant); err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "invalid role %q (want %q or %q)", req.Role, roleOperator, roleTenant)
		return
	}
	plaintext, created, err := s.createKey(req.Role, req.Tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if err := s.env.Manager.Audit.Log(r.Context(), audit.Record{
		Tenant: created.Tenant,
		Actor:  s.actor(key, r),
		Action: "apikey.create",
		Object: audit.Object{Type: "apikey", ID: created.ID},
		Detail: map[string]string{"role": created.Role, "tenant": created.Tenant},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         created.ID,
		"key":        plaintext, // shown once
		"role":       created.Role,
		"tenant":     created.Tenant,
		"created_at": created.CreatedAt,
	})
}
