package acme

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/ca"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// orderTTL is how long a pending order and its authorizations stay usable.
const orderTTL = 24 * time.Hour

// handleNewOrder implements RFC 8555 §7.4: create an order plus one
// authorization (with http-01 and dns-01 challenges) per dns identifier.
func (s *server) handleNewOrder(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	acct := req.account
	var body struct {
		Identifiers []identifier `json:"identifiers"`
	}
	if err := json.Unmarshal(req.payload, &body); err != nil {
		return errf(http.StatusBadRequest, "malformed", "invalid new-order payload: %v", err)
	}
	if len(body.Identifiers) == 0 {
		return errf(http.StatusBadRequest, "malformed", "order must name at least one identifier")
	}
	for _, ident := range body.Identifiers {
		if ident.Type != "dns" {
			return errf(http.StatusBadRequest, "unsupportedIdentifier", "identifier type %q is not supported (dns only)", ident.Type)
		}
		if ident.Value == "" {
			return errf(http.StatusBadRequest, "malformed", "empty dns identifier")
		}
	}

	orderID, err := randID()
	if err != nil {
		return err
	}
	o := order{
		ID:          orderID,
		AccountID:   acct.ID,
		Status:      statusPending,
		Expires:     time.Now().UTC().Add(orderTTL),
		Identifiers: body.Identifiers,
	}
	for _, ident := range body.Identifiers {
		azID, err := randID()
		if err != nil {
			return err
		}
		az := authz{
			ID:         azID,
			OrderID:    orderID,
			AccountID:  acct.ID,
			Identifier: ident,
			Status:     statusPending,
			Expires:    o.Expires,
		}
		types := []string{"http-01", "dns-01"}
		if strings.HasPrefix(ident.Value, "*.") {
			types = []string{"dns-01"} // wildcards are dns-01 only (RFC 8555 §7.4.1)
		}
		for _, typ := range types {
			chID, err := randID()
			if err != nil {
				return err
			}
			token, err := randToken()
			if err != nil {
				return err
			}
			ch := challenge{ID: chID, AuthzID: azID, Type: typ, Token: token, Status: statusPending}
			if err := s.st.PutJSON(challengesBucket(req.tenant), chID, &ch); err != nil {
				return fmt.Errorf("acme: storing challenge: %w", err)
			}
			az.ChallengeIDs = append(az.ChallengeIDs, chID)
		}
		if err := s.st.PutJSON(authzsBucket(req.tenant), azID, &az); err != nil {
			return fmt.Errorf("acme: storing authorization: %w", err)
		}
		o.AuthzIDs = append(o.AuthzIDs, azID)
	}
	if err := s.st.PutJSON(ordersBucket(req.tenant), orderID, &o); err != nil {
		return fmt.Errorf("acme: storing order: %w", err)
	}
	if err := s.audit(r, req.tenant, "acme.order.new", acct.ID, audit.Object{Type: "acme-order", ID: orderID},
		map[string]string{"identifiers": identifierSummary(o.Identifiers)}); err != nil {
		return err
	}
	w.Header().Set("Location", s.url(req.tenant, "/order/"+orderID))
	writeJSON(w, http.StatusCreated, s.orderJSON(req.tenant, &o))
	return nil
}

// handleOrder serves order status via POST-as-GET.
func (s *server) handleOrder(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	o, err := s.loadOrder(req, r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set("Location", s.url(req.tenant, "/order/"+o.ID))
	writeJSON(w, http.StatusOK, s.orderJSON(req.tenant, o))
	return nil
}

// handleFinalize implements RFC 8555 §7.4: verify the CSR against the order
// and issue through the tenant's default profile — the same internal/ca path
// as the REST API, so audit and profile enforcement stay uniform (ADR-0007).
func (s *server) handleFinalize(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	o, err := s.loadOrder(req, r.PathValue("id"))
	if err != nil {
		return err
	}
	if o.Status != statusReady {
		return errf(http.StatusForbidden, "orderNotReady", "order is %s, not ready", o.Status)
	}
	var body struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(req.payload, &body); err != nil {
		return errf(http.StatusBadRequest, "malformed", "invalid finalize payload: %v", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(body.CSR)
	if err != nil {
		return errf(http.StatusBadRequest, "badCSR", "invalid csr encoding: %v", err)
	}
	csr, err := pkix.ParseCertificateRequest(der)
	if err != nil {
		return errf(http.StatusBadRequest, "badCSR", "parsing CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return errf(http.StatusBadRequest, "badCSR", "CSR signature invalid: %v", err)
	}
	if err := checkCSRIdentifiers(csr, o.Identifiers); err != nil {
		return err
	}

	issued, err := s.mgr.Issue(r.Context(), ca.IssueRequest{
		Tenant:  req.tenant,
		Profile: "default",
		CSR:     csr,
		Actor:   audit.Actor{Type: "acme", ID: req.account.ID},
	})
	if err != nil {
		return errf(http.StatusForbidden, "badCSR", "issuance refused: %v", err)
	}

	certID, err := randID()
	if err != nil {
		return err
	}
	serial := issued[0].Cert.X509.SerialNumber.String()
	sc := storedCert{
		ID:        certID,
		AccountID: req.account.ID,
		Serial:    serial,
		ChainPEM:  pkix.EncodeChainPEM(issued[0].Path),
		CreatedAt: time.Now().UTC(),
	}
	if err := s.st.PutJSON(certsBucket(req.tenant), certID, &sc); err != nil {
		return fmt.Errorf("acme: storing certificate: %w", err)
	}
	o.Status = statusValid
	o.CertID = certID
	if err := s.st.PutJSON(ordersBucket(req.tenant), o.ID, o); err != nil {
		return fmt.Errorf("acme: updating order: %w", err)
	}
	if err := s.audit(r, req.tenant, "acme.order.finalize", req.account.ID, audit.Object{Type: "acme-order", ID: o.ID},
		map[string]string{"serial": serial, "identifiers": identifierSummary(o.Identifiers)}); err != nil {
		return err
	}
	w.Header().Set("Location", s.url(req.tenant, "/order/"+o.ID))
	writeJSON(w, http.StatusOK, s.orderJSON(req.tenant, o))
	return nil
}

// handleCert serves the issued chain via POST-as-GET (RFC 8555 §7.4.2).
func (s *server) handleCert(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	id := r.PathValue("id")
	var sc storedCert
	if err := s.st.GetJSON(certsBucket(req.tenant), id, &sc); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errf(http.StatusNotFound, "malformed", "unknown certificate %q", id)
		}
		return fmt.Errorf("acme: loading certificate: %w", err)
	}
	if req.account == nil || sc.AccountID != req.account.ID {
		return errf(http.StatusForbidden, "unauthorized", "certificate belongs to another account")
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sc.ChainPEM)
	return nil
}

// handleRevoke implements RFC 8555 §7.6: the requester must be the account
// that ordered the certificate, or prove possession of the certificate key.
func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request, req *jwsRequest) error {
	var body struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}
	if err := json.Unmarshal(req.payload, &body); err != nil {
		return errf(http.StatusBadRequest, "malformed", "invalid revoke payload: %v", err)
	}
	der, err := base64.RawURLEncoding.DecodeString(body.Certificate)
	if err != nil {
		return errf(http.StatusBadRequest, "malformed", "invalid certificate encoding: %v", err)
	}
	cert, err := pkix.ParseCertificate(der)
	if err != nil {
		return errf(http.StatusBadRequest, "malformed", "parsing certificate: %v", err)
	}
	if body.Reason < 0 || body.Reason > 10 {
		return errf(http.StatusBadRequest, "badRevocationReason", "reason code %d out of range", body.Reason)
	}
	serial := cert.X509.SerialNumber.String()

	var actorID string
	if req.account != nil {
		owned := false
		err := store.ForEachJSON(s.st, certsBucket(req.tenant), func(_ string, sc storedCert) error {
			if sc.Serial == serial && sc.AccountID == req.account.ID {
				owned = true
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("acme: scanning certificates: %w", err)
		}
		if !owned {
			return errf(http.StatusForbidden, "unauthorized", "account did not order certificate %s", serial)
		}
		actorID = req.account.ID
	} else {
		// Bare-jwk revocation: the JWS key must be the certificate key.
		eq, ok := req.key.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !eq.Equal(cert.PublicKey) {
			return errf(http.StatusForbidden, "unauthorized", "JWS key does not match certificate key")
		}
		actorID = "key:" + req.thumb
	}

	if err := s.mgr.Revoke(r.Context(), req.tenant, serial, body.Reason, audit.Actor{Type: "acme", ID: actorID}); err != nil {
		switch {
		case strings.Contains(err.Error(), "already revoked"):
			return errf(http.StatusBadRequest, "alreadyRevoked", "certificate %s is already revoked", serial)
		case strings.Contains(err.Error(), "unknown certificate"):
			return errf(http.StatusNotFound, "malformed", "certificate %s was not issued by this tenant", serial)
		default:
			return err
		}
	}
	if err := s.audit(r, req.tenant, "acme.cert.revoke", actorID, audit.Object{Type: "cert", ID: serial},
		map[string]string{"reason_code": fmt.Sprint(body.Reason)}); err != nil {
		return err
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

// loadOrder loads an order and enforces account ownership (object URLs are
// capability URLs bound to the account, ADR-0007).
func (s *server) loadOrder(req *jwsRequest, id string) (*order, error) {
	var o order
	if err := s.st.GetJSON(ordersBucket(req.tenant), id, &o); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errf(http.StatusNotFound, "malformed", "unknown order %q", id)
		}
		return nil, fmt.Errorf("acme: loading order: %w", err)
	}
	if req.account == nil || o.AccountID != req.account.ID {
		return nil, errf(http.StatusForbidden, "unauthorized", "order belongs to another account")
	}
	return &o, nil
}

// orderJSON renders the RFC 8555 §7.1.3 order object.
func (s *server) orderJSON(tenant string, o *order) orderResp {
	resp := orderResp{
		Status:      o.Status,
		Expires:     o.Expires.UTC().Format(time.RFC3339),
		Identifiers: o.Identifiers,
		Finalize:    s.url(tenant, "/order/"+o.ID+"/finalize"),
		Error:       o.Error,
	}
	for _, azID := range o.AuthzIDs {
		resp.Authorizations = append(resp.Authorizations, s.url(tenant, "/authz/"+azID))
	}
	if o.CertID != "" {
		resp.Certificate = s.url(tenant, "/cert/"+o.CertID)
	}
	return resp
}

// checkCSRIdentifiers requires the CSR's names to exactly match the order's
// dns identifiers (RFC 8555 §7.4).
func checkCSRIdentifiers(csr *pkix.CertificateRequest, idents []identifier) error {
	if len(csr.EmailAddresses) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 {
		return errf(http.StatusBadRequest, "badCSR", "CSR may only request dns names")
	}
	want := make(map[string]bool, len(idents))
	for _, ident := range idents {
		want[ident.Value] = true
	}
	got := make(map[string]bool, len(csr.DNSNames))
	for _, d := range csr.DNSNames {
		got[d] = true
	}
	if cn := csr.Subject.CommonName; cn != "" && !want[cn] {
		return errf(http.StatusBadRequest, "badCSR", "CSR common name %q is not an order identifier", cn)
	}
	for d := range got {
		if !want[d] {
			return errf(http.StatusBadRequest, "badCSR", "CSR names %q, which the order does not authorize", d)
		}
	}
	for v := range want {
		if !got[v] {
			return errf(http.StatusBadRequest, "badCSR", "CSR is missing order identifier %q", v)
		}
	}
	return nil
}

func identifierSummary(idents []identifier) string {
	vals := make([]string, len(idents))
	for i, ident := range idents {
		vals[i] = ident.Value
	}
	return strings.Join(vals, ",")
}
