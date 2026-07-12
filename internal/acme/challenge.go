package acme

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mnemoshare/mnemoca/internal/store"
)

// handleAuthz serves an authorization via POST-as-GET (RFC 8555 §7.5).
func (s *server) handleAuthz(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	az, err := s.loadAuthz(r.Context(), req, r.PathValue("id"))
	if err != nil {
		return err
	}
	resp := authzResp{
		Identifier: az.Identifier,
		Status:     az.Status,
		Expires:    az.Expires.UTC().Format(time.RFC3339),
		Wildcard:   strings.HasPrefix(az.Identifier.Value, "*."),
	}
	for _, chID := range az.ChallengeIDs {
		var ch challenge
		if err := store.GetJSON(r.Context(), s.st, challengesBucket(req.tenant), chID, &ch); err != nil {
			return fmt.Errorf("acme: loading challenge: %w", err)
		}
		resp.Challenges = append(resp.Challenges, s.challengeJSON(req.tenant, &ch))
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// handleChallenge serves a challenge; a POST with a JSON body (typically {})
// triggers validation, which runs synchronously in v0.
func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	id := r.PathValue("id")
	var ch challenge
	if err := store.GetJSON(r.Context(), s.st, challengesBucket(req.tenant), id, &ch); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errf(http.StatusNotFound, "malformed", "unknown challenge %q", id)
		}
		return fmt.Errorf("acme: loading challenge: %w", err)
	}
	var az authz
	if err := store.GetJSON(r.Context(), s.st, authzsBucket(req.tenant), ch.AuthzID, &az); err != nil {
		return fmt.Errorf("acme: loading authorization: %w", err)
	}
	if req.account == nil || az.AccountID != req.account.ID {
		return errf(http.StatusForbidden, "unauthorized", "challenge belongs to another account")
	}

	if len(req.payload) > 0 && ch.Status == statusPending {
		if !json.Valid(req.payload) {
			return errf(http.StatusBadRequest, "malformed", "challenge response must be a JSON object")
		}
		if err := s.validateChallenge(r.Context(), req.tenant, &az, &ch, req.account); err != nil {
			return err
		}
	}
	w.Header().Set("Link", fmt.Sprintf("<%s>;rel=%q", s.url(req.tenant, "/authz/"+az.ID), "up"))
	writeJSON(w, http.StatusOK, s.challengeJSON(req.tenant, &ch))
	return nil
}

// validateChallenge performs http-01 or dns-01 validation and persists the
// resulting challenge, authorization, and order state.
func (s *server) validateChallenge(ctx context.Context, tenant string, az *authz, ch *challenge, acct *account) error {
	keyAuthz := ch.Token + "." + acct.Thumbprint
	var vErr error
	switch ch.Type {
	case "http-01":
		vErr = s.checkHTTP01(ctx, az.Identifier.Value, ch.Token, keyAuthz)
	case "dns-01":
		vErr = s.checkDNS01(ctx, strings.TrimPrefix(az.Identifier.Value, "*."), keyAuthz)
	default:
		vErr = fmt.Errorf("unsupported challenge type %q", ch.Type)
	}
	if vErr != nil {
		ch.Status = statusInvalid
		ch.Error = &problem{Type: errURN + "incorrectResponse", Detail: vErr.Error(), Status: http.StatusForbidden}
		az.Status = statusInvalid
	} else {
		ch.Status = statusValid
		ch.Validated = time.Now().UTC()
		az.Status = statusValid
	}
	if err := store.PutJSON(ctx, s.st, challengesBucket(tenant), ch.ID, ch); err != nil {
		return fmt.Errorf("acme: storing challenge: %w", err)
	}
	if err := store.PutJSON(ctx, s.st, authzsBucket(tenant), az.ID, az); err != nil {
		return fmt.Errorf("acme: storing authorization: %w", err)
	}
	return s.updateOrderStatus(ctx, tenant, az.OrderID)
}

// updateOrderStatus recomputes a pending order after an authorization
// changes: all-valid → ready, any-invalid → invalid.
func (s *server) updateOrderStatus(ctx context.Context, tenant, orderID string) error {
	var o order
	if err := store.GetJSON(ctx, s.st, ordersBucket(tenant), orderID, &o); err != nil {
		return fmt.Errorf("acme: loading order: %w", err)
	}
	if o.Status != statusPending {
		return nil
	}
	allValid := true
	for _, azID := range o.AuthzIDs {
		var az authz
		if err := store.GetJSON(ctx, s.st, authzsBucket(tenant), azID, &az); err != nil {
			return fmt.Errorf("acme: loading authorization: %w", err)
		}
		switch az.Status {
		case statusInvalid:
			o.Status = statusInvalid
			o.Error = &problem{Type: errURN + "unauthorized", Detail: "authorization for " + az.Identifier.Value + " failed", Status: http.StatusForbidden}
			return store.PutJSON(ctx, s.st, ordersBucket(tenant), orderID, &o)
		case statusValid:
		default:
			allValid = false
		}
	}
	if !allValid {
		return nil
	}
	o.Status = statusReady
	return store.PutJSON(ctx, s.st, ordersBucket(tenant), orderID, &o)
}

// checkHTTP01 fetches http://{host}:{port}/.well-known/acme-challenge/{token}
// and requires the body to be the key authorization (RFC 8555 §8.3).
func (s *server) checkHTTP01(ctx context.Context, host, token, keyAuthz string) error {
	u := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s",
		net.JoinHostPort(host, strconv.Itoa(s.httpPort)), token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("building challenge request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: status %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return fmt.Errorf("reading challenge response: %w", err)
	}
	if strings.TrimSpace(string(body)) != keyAuthz {
		return fmt.Errorf("key authorization mismatch at %s", u)
	}
	return nil
}

// checkDNS01 requires a TXT record at _acme-challenge.{host} equal to
// base64url(sha256(keyAuthz)) (RFC 8555 §8.4).
func (s *server) checkDNS01(ctx context.Context, host, keyAuthz string) error {
	sum := sha256.Sum256([]byte(keyAuthz))
	want := rawB64(sum[:])
	name := "_acme-challenge." + host
	txts, err := s.resolver.LookupTXT(ctx, name)
	if err != nil {
		return fmt.Errorf("looking up TXT %s: %w", name, err)
	}
	if !slices.Contains(txts, want) {
		return fmt.Errorf("no TXT record at %s matches the key authorization digest", name)
	}
	return nil
}

// loadAuthz loads an authorization and enforces account ownership.
func (s *server) loadAuthz(ctx context.Context, req *jwsRequest, id string) (*authz, error) {
	var az authz
	if err := store.GetJSON(ctx, s.st, authzsBucket(req.tenant), id, &az); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errf(http.StatusNotFound, "malformed", "unknown authorization %q", id)
		}
		return nil, fmt.Errorf("acme: loading authorization: %w", err)
	}
	if req.account == nil || az.AccountID != req.account.ID {
		return nil, errf(http.StatusForbidden, "unauthorized", "authorization belongs to another account")
	}
	return &az, nil
}

// challengeJSON renders the RFC 8555 §8 challenge object.
func (s *server) challengeJSON(tenant string, ch *challenge) challengeResp {
	resp := challengeResp{
		Type:   ch.Type,
		URL:    s.url(tenant, "/chall/"+ch.ID),
		Token:  ch.Token,
		Status: ch.Status,
		Error:  ch.Error,
	}
	if !ch.Validated.IsZero() {
		resp.Validated = ch.Validated.UTC().Format(time.RFC3339)
	}
	return resp
}
