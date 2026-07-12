// Package acme implements the RFC 8555 subset MnemoCA serves to ACME
// clients such as cert-manager (ADR-0007): per-tenant directories,
// ES256/RS256/EdDSA account keys, http-01 and dns-01 challenges, and
// finalize/revoke wired into the same internal/ca paths as the REST API.
package acme

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Object status values (RFC 8555 §7.1.6).
const (
	statusPending = "pending"
	statusReady   = "ready"
	statusValid   = "valid"
	statusInvalid = "invalid"
)

// errURN prefixes ACME error codes into their registered URN namespace.
const errURN = "urn:ietf:params:acme:error:"

// problem is an RFC 7807 problem document carrying an ACME error type.
type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
	Status int    `json:"status,omitempty"`
}

// acmeError is an error that renders as an ACME problem document.
type acmeError struct {
	status int
	code   string // short registered code, e.g. "badNonce"
	detail string
}

func (e *acmeError) Error() string { return fmt.Sprintf("acme: %s: %s", e.code, e.detail) }

// errf builds an acmeError with a formatted detail message.
func errf(status int, code, format string, args ...any) *acmeError {
	return &acmeError{status: status, code: code, detail: fmt.Sprintf(format, args...)}
}

// identifier is an ACME identifier; only type "dns" is supported (ADR-0007).
type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// account is a stored ACME account, keyed by ID in acme/<tenant>/accounts.
type account struct {
	ID         string          `json:"id"`
	Thumbprint string          `json:"thumbprint"` // RFC 7638 JWK thumbprint
	JWK        json.RawMessage `json:"jwk"`
	Contact    []string        `json:"contact,omitempty"`
	Status     string          `json:"status"`
	EAB        string          `json:"eab,omitempty"` // EAB key ID bound at registration
	CreatedAt  time.Time       `json:"created_at"`
}

// order is a stored ACME order, keyed by ID in acme/<tenant>/orders.
type order struct {
	ID          string       `json:"id"`
	AccountID   string       `json:"account_id"`
	Status      string       `json:"status"`
	Expires     time.Time    `json:"expires"`
	Identifiers []identifier `json:"identifiers"`
	AuthzIDs    []string     `json:"authz_ids"`
	CertID      string       `json:"cert_id,omitempty"`
	Error       *problem     `json:"error,omitempty"`
}

// authz is a stored authorization, keyed by ID in acme/<tenant>/authzs.
type authz struct {
	ID           string     `json:"id"`
	OrderID      string     `json:"order_id"`
	AccountID    string     `json:"account_id"`
	Identifier   identifier `json:"identifier"`
	Status       string     `json:"status"`
	Expires      time.Time  `json:"expires"`
	ChallengeIDs []string   `json:"challenge_ids"`
}

// challenge is a stored challenge, keyed by ID in acme/<tenant>/challenges.
type challenge struct {
	ID        string    `json:"id"`
	AuthzID   string    `json:"authz_id"`
	Type      string    `json:"type"` // "http-01" | "dns-01"
	Token     string    `json:"token"`
	Status    string    `json:"status"`
	Validated time.Time `json:"validated,omitempty"`
	Error     *problem  `json:"error,omitempty"`
}

// storedCert is an issued chain, keyed by ID in acme/<tenant>/certs.
type storedCert struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Serial    string    `json:"serial"`
	ChainPEM  []byte    `json:"chain_pem"`
	CreatedAt time.Time `json:"created_at"`
}

// eabKey is a per-tenant external account binding HMAC key.
type eabKey struct {
	KID       string    `json:"kid"`
	Key       []byte    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

// Wire shapes (RFC 8555 §7.1).

type accountResp struct {
	Status  string   `json:"status"`
	Contact []string `json:"contact,omitempty"`
}

type orderResp struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires"`
	Identifiers    []identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Error          *problem     `json:"error,omitempty"`
}

type challengeResp struct {
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Token     string   `json:"token"`
	Status    string   `json:"status"`
	Validated string   `json:"validated,omitempty"`
	Error     *problem `json:"error,omitempty"`
}

type authzResp struct {
	Identifier identifier      `json:"identifier"`
	Status     string          `json:"status"`
	Expires    string          `json:"expires"`
	Challenges []challengeResp `json:"challenges"`
	Wildcard   bool            `json:"wildcard,omitempty"`
}

// Bucket paths: everything ACME lives under acme/<tenant>/... (ADR-0006).
func acmeBucket(tenant, kind string) []string { return []string{"acme", tenant, kind} }

func accountsBucket(t string) []string   { return acmeBucket(t, "accounts") }
func ordersBucket(t string) []string     { return acmeBucket(t, "orders") }
func authzsBucket(t string) []string     { return acmeBucket(t, "authzs") }
func challengesBucket(t string) []string { return acmeBucket(t, "challenges") }
func certsBucket(t string) []string      { return acmeBucket(t, "certs") }
func eabBucket(t string) []string        { return acmeBucket(t, "eab") }
func nonceBucket(t string) []string      { return acmeBucket(t, "nonces") }

// randID returns a crypto/rand hex identifier for ACME objects.
func randID() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("acme: generating id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// randToken returns a base64url challenge token with ≥128 bits of entropy
// (RFC 8555 §8.3).
func randToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("acme: generating token: %w", err)
	}
	return rawB64(b[:]), nil
}
