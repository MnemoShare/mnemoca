package acme

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// CreateEABKey mints an external account binding HMAC key for the tenant
// and returns its key ID plus the base64url-encoded key — what an operator
// hands to a client (e.g. a cert-manager Issuer's keySecretRef).
func CreateEABKey(ctx context.Context, st store.Store, tenant string) (string, string, error) {
	kid, err := randID()
	if err != nil {
		return "", "", err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", "", fmt.Errorf("acme: generating EAB key: %w", err)
	}
	ek := eabKey{KID: kid, Key: key, CreatedAt: time.Now().UTC()}
	if err := store.PutJSON(ctx, st, eabBucket(tenant), kid, &ek); err != nil {
		return "", "", fmt.Errorf("acme: storing EAB key: %w", err)
	}
	return kid, base64.RawURLEncoding.EncodeToString(key), nil
}

// handleNewAccount implements RFC 8555 §7.3: create an account or return
// the existing one keyed by JWK thumbprint.
func (s *server) handleNewAccount(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	if req.account != nil {
		return errf(http.StatusBadRequest, "malformed", "new-account requires jwk authentication")
	}
	var body struct {
		Contact                []string        `json:"contact"`
		TermsOfServiceAgreed   bool            `json:"termsOfServiceAgreed"`
		OnlyReturnExisting     bool            `json:"onlyReturnExisting"`
		ExternalAccountBinding json.RawMessage `json:"externalAccountBinding"`
	}
	if len(req.payload) > 0 {
		if err := json.Unmarshal(req.payload, &body); err != nil {
			return errf(http.StatusBadRequest, "malformed", "invalid new-account payload: %v", err)
		}
	}

	existing, err := s.accountByThumbprint(r.Context(), req.tenant, req.thumb)
	if err != nil {
		return err
	}
	if existing != nil {
		w.Header().Set("Location", s.url(req.tenant, "/account/"+existing.ID))
		writeJSON(w, http.StatusOK, accountResp{Status: existing.Status, Contact: existing.Contact})
		return nil
	}
	if body.OnlyReturnExisting {
		return errf(http.StatusBadRequest, "accountDoesNotExist", "no account matches this key")
	}

	var eabKID string
	switch {
	case len(body.ExternalAccountBinding) > 0:
		eabKID, err = s.verifyEAB(r.Context(), req.tenant, req.jwk, body.ExternalAccountBinding, s.url(req.tenant, "/new-account"))
		if err != nil {
			return err
		}
	case s.opts.RequireEAB:
		return errf(http.StatusBadRequest, "externalAccountRequired", "this tenant requires an external account binding")
	}

	id, err := randID()
	if err != nil {
		return err
	}
	acct := account{
		ID:         id,
		Thumbprint: req.thumb,
		JWK:        req.jwk,
		Contact:    body.Contact,
		Status:     statusValid,
		EAB:        eabKID,
		CreatedAt:  time.Now().UTC(),
	}
	if err := store.PutJSON(r.Context(), s.st, accountsBucket(req.tenant), id, &acct); err != nil {
		return fmt.Errorf("acme: storing account: %w", err)
	}
	if err := s.audit(r, req.tenant, "acme.account.new", id, audit.Object{Type: "acme-account", ID: id},
		map[string]string{"thumbprint": req.thumb, "eab_kid": eabKID}); err != nil {
		return err
	}
	w.Header().Set("Location", s.url(req.tenant, "/account/"+id))
	writeJSON(w, http.StatusCreated, accountResp{Status: acct.Status, Contact: acct.Contact})
	return nil
}

// handleAccount serves the account URL: POST-as-GET returns the account,
// non-empty payloads may update contact. Deactivation and key rollover are
// deferred (ADR-0007) and rejected cleanly.
func (s *server) handleAccount(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	id := r.PathValue("id")
	if req.account == nil || req.account.ID != id {
		return errf(http.StatusForbidden, "unauthorized", "kid does not match account URL")
	}
	acct := req.account
	if len(req.payload) > 0 {
		var body struct {
			Contact []string `json:"contact"`
			Status  string   `json:"status"`
		}
		if err := json.Unmarshal(req.payload, &body); err != nil {
			return errf(http.StatusBadRequest, "malformed", "invalid account update payload: %v", err)
		}
		if body.Status != "" && body.Status != acct.Status {
			return errf(http.StatusBadRequest, "malformed", "account status changes are not supported")
		}
		if body.Contact != nil {
			acct.Contact = body.Contact
			if err := store.PutJSON(r.Context(), s.st, accountsBucket(req.tenant), acct.ID, acct); err != nil {
				return fmt.Errorf("acme: updating account: %w", err)
			}
		}
	}
	w.Header().Set("Location", s.url(req.tenant, "/account/"+acct.ID))
	writeJSON(w, http.StatusOK, accountResp{Status: acct.Status, Contact: acct.Contact})
	return nil
}

// accountByThumbprint scans the tenant's accounts for one bound to thumb.
func (s *server) accountByThumbprint(ctx context.Context, tenant, thumb string) (*account, error) {
	var found *account
	err := store.ForEachJSON(ctx, s.st, accountsBucket(tenant), func(_ string, a account) error {
		if a.Thumbprint == thumb {
			found = &a
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("acme: scanning accounts: %w", err)
	}
	return found, nil
}

// verifyEAB checks an externalAccountBinding: an HS256 flattened JWS whose
// payload is the account JWK, MAC'd with a per-tenant EAB key (RFC 8555 §7.3.4).
func (s *server) verifyEAB(ctx context.Context, tenant string, outerJWK json.RawMessage, raw json.RawMessage, reqURL string) (string, error) {
	var jws flatJWS
	if err := json.Unmarshal(raw, &jws); err != nil {
		return "", errf(http.StatusBadRequest, "malformed", "invalid externalAccountBinding: %v", err)
	}
	protBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return "", errf(http.StatusBadRequest, "malformed", "invalid EAB protected header encoding: %v", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(protBytes, &hdr); err != nil {
		return "", errf(http.StatusBadRequest, "malformed", "invalid EAB protected header: %v", err)
	}
	if hdr.Alg != "HS256" {
		return "", errf(http.StatusBadRequest, "badSignatureAlgorithm", "EAB alg must be HS256, got %q", hdr.Alg)
	}
	if hdr.URL != "" && hdr.URL != reqURL {
		return "", errf(http.StatusUnauthorized, "unauthorized", "EAB url %q does not match request URL", hdr.URL)
	}

	// The EAB payload must be the account key being registered.
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return "", errf(http.StatusBadRequest, "malformed", "invalid EAB payload encoding: %v", err)
	}
	innerThumb, err := jwkThumbprint(payload)
	if err != nil {
		return "", err
	}
	outerThumb, err := jwkThumbprint(outerJWK)
	if err != nil {
		return "", err
	}
	if innerThumb != outerThumb {
		return "", errf(http.StatusUnauthorized, "unauthorized", "EAB payload key does not match account key")
	}

	var ek eabKey
	if err := store.GetJSON(ctx, s.st, eabBucket(tenant), hdr.KID, &ek); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", errf(http.StatusUnauthorized, "unauthorized", "unknown EAB key %q", hdr.KID)
		}
		return "", fmt.Errorf("acme: loading EAB key: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil {
		return "", errf(http.StatusBadRequest, "malformed", "invalid EAB signature encoding: %v", err)
	}
	mac := hmac.New(sha256.New, ek.Key)
	mac.Write([]byte(jws.Protected + "." + jws.Payload))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return "", errf(http.StatusUnauthorized, "unauthorized", "EAB MAC verification failed")
	}
	return hdr.KID, nil
}
