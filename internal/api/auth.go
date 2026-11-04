package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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

const (
	keyPrefix      = "mnemoca_"
	keyIDBytes     = 8
	keySecretBytes = 32

	// BootstrapKeyEnv names the env var (and serve flag default) pointing at
	// the file holding the operator key to adopt on first start.
	BootstrapKeyEnv = "MNEMOCA_BOOTSTRAP_API_KEY_FILE"
	// BootstrapKeyFileName is the file written under the data directory when
	// a bolt-mode first start mints its own key.
	BootstrapKeyFileName = "bootstrap-api-key"

	bootstrapMintedID = "0000000000000000"
)

var errMalformedKey = errors.New("malformed API key: want mnemoca_<16 lowercase hex>_<64 lowercase hex>")

var apiKeysBucket = []string{"apikeys"}

// apiKey is the stored form of an API key: only the SHA-256 of the secret is
// persisted; the plaintext is shown exactly once at creation.
type apiKey struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"` // hex SHA-256 of the secret
	Role      string    `json:"role"`
	Tenant    string    `json:"tenant"`
	CreatedAt time.Time `json:"created_at"`
	// Bootstrap marks the first-start operator key; Audited records that its
	// creation was written to the audit log.
	Bootstrap bool `json:"bootstrap,omitempty"`
	Audited   bool `json:"audited,omitempty"`
}

// allows reports whether the key may act on tenant.
func (k *apiKey) allows(tenant string) bool {
	return k.Role == roleOperator || (k.Role == roleTenant && k.Tenant == tenant)
}

func (s *server) actor(k *apiKey, r *http.Request) audit.Actor {
	return audit.Actor{Type: "apikey", ID: k.ID, IP: r.RemoteAddr}
}

// newKeyRecord builds the stored record for a key whose secret is known.
func newKeyRecord(id, secret, role, tenant string) *apiKey {
	sum := sha256.Sum256([]byte(secret))
	return &apiKey{
		ID:        id,
		Hash:      hex.EncodeToString(sum[:]),
		Role:      role,
		Tenant:    tenant,
		CreatedAt: time.Now().UTC(),
	}
}

// mintKey generates a random id and secret and returns the plaintext bearer
// token with its stored record (not yet persisted).
func mintKey(role, tenant string) (string, *apiKey, error) {
	idBytes := make([]byte, keyIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return "", nil, err
	}
	secretBytes := make([]byte, keySecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", nil, err
	}
	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	return keyPrefix + id + "_" + secret, newKeyRecord(id, secret, role, tenant), nil
}

// createKey mints and stores a new API key, returning the plaintext bearer
// token (shown once) and the stored record.
func (s *server) createKey(ctx context.Context, role, tenant string) (string, *apiKey, error) {
	token, key, err := mintKey(role, tenant)
	if err != nil {
		return "", nil, err
	}
	if err := store.PutJSON(ctx, s.env.Store, apiKeysBucket, key.ID, key); err != nil {
		return "", nil, err
	}
	return token, key, nil
}

// parseKey validates a bearer token in the format mintKey produces and
// returns its id and secret.
func parseKey(token string) (id, secret string, err error) {
	rest, ok := strings.CutPrefix(token, keyPrefix)
	if !ok {
		return "", "", errMalformedKey
	}
	id, secret, ok = strings.Cut(rest, "_")
	if !ok || len(id) != 2*keyIDBytes || len(secret) != 2*keySecretBytes ||
		!isLowerHex(id) || !isLowerHex(secret) {
		return "", "", errMalformedKey
	}
	return id, secret, nil
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// bootstrapKey makes sure an operator key exists on first start. Creation is
// an atomic insert-if-absent, so concurrent replicas on a shared store end up
// with exactly one bootstrap key. The plaintext is never logged. The audit
// record is written after the insert and then flagged on the key; a start that
// finds an unaudited bootstrap key writes the record, so a failed audit write
// is repaired by a restart.
func (s *server) bootstrapKey() error {
	ctx := context.Background()

	var supplied *apiKey
	if s.opts.BootstrapKeyFile != "" {
		data, err := os.ReadFile(s.opts.BootstrapKeyFile)
		if err != nil {
			return fmt.Errorf("reading bootstrap key file: %w", err)
		}
		id, secret, err := parseKey(strings.TrimSpace(string(data)))
		if err != nil {
			return fmt.Errorf("bootstrap key file: %w", err)
		}
		supplied = newKeyRecord(id, secret, roleOperator, "")
		supplied.Bootstrap = true
	}

	exists := false
	var unaudited []string
	err := store.ForEachJSON(ctx, s.env.Store, apiKeysBucket, func(id string, k apiKey) error {
		exists = true
		if k.Bootstrap && !k.Audited {
			unaudited = append(unaudited, id)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if exists {
		for _, id := range unaudited {
			if err := s.auditBootstrap(ctx, id); err != nil {
				return err
			}
		}
		if supplied != nil {
			if _, err := s.env.Store.Get(ctx, apiKeysBucket, supplied.ID); errors.Is(err, store.ErrNotFound) {
				fmt.Fprintf(os.Stderr, "mnemoca: warning: bootstrap key %s from %s was not adopted: API keys already exist\n",
					supplied.ID, BootstrapKeyEnv)
			} else if err != nil {
				return err
			}
		}
		return nil
	}

	var created bool
	var id string
	switch {
	case supplied != nil:
		id = supplied.ID
		created, err = s.insertKey(ctx, supplied)
	case s.env.DB != "bolt":
		return fmt.Errorf("no operator API key exists and the %s store will not auto-mint one: set %s to a file holding %s<16 hex>_<64 hex>",
			s.env.DB, BootstrapKeyEnv, keyPrefix)
	default:
		id = bootstrapMintedID
		created, err = s.mintBootstrapFile(ctx)
	}
	if err != nil || !created {
		return err
	}
	return s.auditBootstrap(ctx, id)
}

// auditBootstrap writes the bootstrap creation record and flags the key as
// audited.
func (s *server) auditBootstrap(ctx context.Context, id string) error {
	if err := s.env.Manager.Audit.Log(ctx, audit.Record{
		Actor:  audit.Actor{Type: "system", ID: "mnemoca"},
		Action: "apikey.create",
		Object: audit.Object{Type: "apikey", ID: id},
		Detail: map[string]string{"role": roleOperator, "bootstrap": "true"},
	}); err != nil {
		return fmt.Errorf("auditing bootstrap key: %w", err)
	}
	return store.UpdateJSON(ctx, s.env.Store, apiKeysBucket, id, false, func(k *apiKey) error {
		k.Audited = true
		return nil
	})
}

func (s *server) insertKey(ctx context.Context, key *apiKey) (bool, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return false, err
	}
	return s.env.Store.PutIfAbsent(ctx, apiKeysBucket, key.ID, data)
}

// mintBootstrapFile creates a random operator key under a fixed id, so
// concurrent starters collide on the insert. The plaintext is written to a
// private temp file (O_EXCL: never follows a symlink, never reuses a file) and
// renamed over the final path only by the starter that won the insert, so
// losers cannot disturb the winner's file and a pre-existing loose file or
// symlink at the path is replaced, not written through.
func (s *server) mintBootstrapFile(ctx context.Context) (bool, error) {
	minted, _, err := mintKey(roleOperator, "")
	if err != nil {
		return false, err
	}
	_, secret, err := parseKey(minted)
	if err != nil {
		return false, err
	}
	key := newKeyRecord(bootstrapMintedID, secret, roleOperator, "")
	key.Bootstrap = true
	token := keyPrefix + bootstrapMintedID + "_" + secret

	tmp, err := writeTempSecret(s.env.Dir, token+"\n")
	if err != nil {
		return false, fmt.Errorf("writing bootstrap key file: %w", err)
	}
	created, err := s.insertKey(ctx, key)
	if err != nil || !created {
		_ = os.Remove(tmp)
		return false, err
	}
	path := filepath.Join(s.env.Dir, BootstrapKeyFileName)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("installing bootstrap key file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "mnemoca: generated bootstrap operator API key; read it from %s\n", path)
	return true, nil
}

// writeTempSecret writes content to a new 0600 file in dir and returns its
// path.
func writeTempSecret(dir, content string) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "."+BootstrapKeyFileName+"."+hex.EncodeToString(suffix))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
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
