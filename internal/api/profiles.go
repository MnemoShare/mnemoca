package api

import (
	"net/http"
	"time"

	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// profileJSON is the wire form of a profile: durations as Go duration
// strings ("720h"), matching the issue endpoint's validity field.
type profileJSON struct {
	Name            string   `json:"name"`
	DefaultValidity string   `json:"default_validity"`
	MaxValidity     string   `json:"max_validity"`
	EKUs            []string `json:"ekus,omitempty"`
	KeyUsages       []string `json:"key_usages,omitempty"`
	AllowedKeyAlgs  []string `json:"allowed_key_algs,omitempty"`
	Hybrid          string   `json:"hybrid,omitempty"`
}

func profileView(p ca.Profile) profileJSON {
	out := profileJSON{
		Name:            p.Name,
		DefaultValidity: p.DefaultValidity.String(),
		MaxValidity:     p.MaxValidity.String(),
		EKUs:            p.EKUs,
		KeyUsages:       p.KeyUsages,
		Hybrid:          string(p.Hybrid),
	}
	// Surface legacy shorthand profiles in explicit EKU form.
	if len(out.EKUs) == 0 {
		if p.ServerAuth {
			out.EKUs = append(out.EKUs, "server_auth")
		}
		if p.ClientAuth {
			out.EKUs = append(out.EKUs, "client_auth")
		}
	}
	for _, alg := range p.AllowedKeyAlgs {
		out.AllowedKeyAlgs = append(out.AllowedKeyAlgs, string(alg))
	}
	return out
}

func (s *server) handleListProfiles(w http.ResponseWriter, r *http.Request, _ *apiKey) {
	t, err := s.env.Manager.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "%v", err)
		return
	}
	out := make([]profileJSON, 0, len(t.Profiles))
	for _, p := range t.Profiles {
		out = append(out, profileView(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profiles":   out,
		"ekus":       ca.ProfileEKUNames(),
		"key_usages": ca.ProfileKeyUsageNames(),
	})
}

func (s *server) handleSetProfile(w http.ResponseWriter, r *http.Request, key *apiKey) {
	var req profileJSON
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	p := ca.Profile{
		Name:      r.PathValue("name"),
		EKUs:      req.EKUs,
		KeyUsages: req.KeyUsages,
		Hybrid:    ca.Chain(req.Hybrid),
	}
	var err error
	if p.DefaultValidity, err = time.ParseDuration(req.DefaultValidity); err != nil {
		writeError(w, http.StatusBadRequest, "invalid default_validity: %v", err)
		return
	}
	if p.MaxValidity, err = time.ParseDuration(req.MaxValidity); err != nil {
		writeError(w, http.StatusBadRequest, "invalid max_validity: %v", err)
		return
	}
	for _, alg := range req.AllowedKeyAlgs {
		p.AllowedKeyAlgs = append(p.AllowedKeyAlgs, pkix.Algorithm(alg))
	}
	if err := s.env.Manager.SetProfile(r.Context(), r.PathValue("id"), p, s.actor(key, r)); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, profileView(p))
}

func (s *server) handleDeleteProfile(w http.ResponseWriter, r *http.Request, key *apiKey) {
	if err := s.env.Manager.DeleteProfile(r.Context(), r.PathValue("id"), r.PathValue("name"), s.actor(key, r)); err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
