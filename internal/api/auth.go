package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// API key roles.
const (
	roleOperator = "operator" // full access, all tenants
	roleTenant   = "tenant"   // scoped to a single tenant
)

const keyPrefix = "mnemoca_"

var apiKeysBucket = []string{"apikeys"}

// apiKey is the stored form of an API key: only the SHA-256 of the secret is
// persisted; the plaintext is shown exactly once at creation.
type apiKey struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"` // hex SHA-256 of the secret
	Role      string    `json:"role"`
	Tenant    string    `json:"tenant"`
	CreatedAt time.Time `json:"created_at"`
}

// allows reports whether the key may act on tenant.
func (k *apiKey) allows(tenant string) bool {
	return k.Role == roleOperator || (k.Role == roleTenant && k.Tenant == tenant)
}

func (s *server) actor(k *apiKey, r *http.Request) audit.Actor {
	return audit.Actor{Type: "apikey", ID: k.ID, IP: r.RemoteAddr}
}

// createKey mints and stores a new API key, returning the plaintext bearer
// token (shown once) and the stored record.
func (s *server) createKey(ctx context.Context, role, tenant string) (string, *apiKey, error) {
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", nil, err
	}
	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	sum := sha256.Sum256([]byte(secret))
	key := apiKey{
		ID:        id,
		Hash:      hex.EncodeToString(sum[:]),
		Role:      role,
		Tenant:    tenant,
		CreatedAt: time.Now().UTC(),
	}
	if err := store.PutJSON(ctx, s.env.Store, apiKeysBucket, id, &key); err != nil {
		return "", nil, err
	}
	return keyPrefix + id + "_" + secret, &key, nil
}

// bootstrapKey generates the first operator key when none exist, printing the
// plaintext once to stderr (the only time it is ever available).
func (s *server) bootstrapKey() error {
	ctx := context.Background()
	exists := false
	err := store.ForEachJSON(ctx, s.env.Store, apiKeysBucket, func(string, apiKey) error {
		exists = true
		return nil
	})
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	plaintext, key, err := s.createKey(ctx, roleOperator, "")
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr,
		"mnemoca: generated bootstrap operator API key (store it now; it will not be shown again):\n  %s\n",
		plaintext)
	return s.env.Manager.Audit.Log(ctx, audit.Record{
		Actor:  audit.Actor{Type: "system", ID: "mnemoca"},
		Action: "apikey.create",
		Object: audit.Object{Type: "apikey", ID: key.ID},
		Detail: map[string]string{"role": key.Role, "bootstrap": "true"},
	})
}

var errUnauthorized = errors.New("api: invalid or missing API key")

// authenticate resolves the Authorization header to a stored key, verifying
// sha256(secret) against the stored hash in constant time.
func (s *server) authenticate(r *http.Request) (*apiKey, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil, errUnauthorized
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(token), keyPrefix)
	if !ok {
		return nil, errUnauthorized
	}
	id, secret, ok := strings.Cut(rest, "_")
	if !ok {
		return nil, errUnauthorized
	}
	var key apiKey
	if err := store.GetJSON(r.Context(), s.env.Store, apiKeysBucket, id, &key); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errUnauthorized
		}
		return nil, err
	}
	stored, err := hex.DecodeString(key.Hash)
	if err != nil {
		return nil, fmt.Errorf("api: corrupt key record %s", id)
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], stored) != 1 {
		return nil, errUnauthorized
	}
	return &key, nil
}

// keyHandler is an authenticated handler.
type keyHandler func(w http.ResponseWriter, r *http.Request, key *apiKey)

// authed wraps a keyHandler with bearer authentication.
func (s *server) authed(next keyHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := s.authenticate(r)
		if err != nil {
			if errors.Is(err, errUnauthorized) {
				writeError(w, http.StatusUnauthorized, "invalid or missing API key")
				return
			}
			writeError(w, http.StatusInternalServerError, "authentication failed")
			return
		}
		next(w, r, key)
	}
}

// operatorOnly restricts a handler to operator-role keys.
func (s *server) operatorOnly(next keyHandler) keyHandler {
	return func(w http.ResponseWriter, r *http.Request, key *apiKey) {
		if key.Role != roleOperator {
			writeError(w, http.StatusForbidden, "operator API key required")
			return
		}
		next(w, r, key)
	}
}

// tenantScoped restricts a handler to keys allowed to act on the {id} tenant.
func (s *server) tenantScoped(next keyHandler) keyHandler {
	return func(w http.ResponseWriter, r *http.Request, key *apiKey) {
		if !key.allows(r.PathValue("id")) {
			writeError(w, http.StatusForbidden, "API key not authorized for tenant %q", r.PathValue("id"))
			return
		}
		next(w, r, key)
	}
}
