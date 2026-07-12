package acme

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/mnemoshare/mnemoca/internal/store"
)

// nonceTTL bounds how long an issued nonce stays usable.
const nonceTTL = 10 * time.Minute

// nonceRec is a stored nonce (bucket acme/<tenant>/nonces, keyed by value).
type nonceRec struct {
	Expires time.Time `json:"expires"`
}

// issueNonce mints a fresh single-use nonce, persists it, and sets the
// Replay-Nonce response header.
func (s *server) issueNonce(ctx context.Context, w http.ResponseWriter, tenant string) error {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Errorf("acme: generating nonce: %w", err)
	}
	n := rawB64(b[:])
	if err := store.PutJSON(ctx, s.st, nonceBucket(tenant), n, nonceRec{Expires: time.Now().Add(nonceTTL)}); err != nil {
		return fmt.Errorf("acme: storing nonce: %w", err)
	}
	w.Header().Set("Replay-Nonce", n)
	w.Header().Set("Cache-Control", "no-store")
	return nil
}

// consumeNonce atomically takes n out of the store and reports whether it
// existed and was unexpired. The single atomic Take (instead of get-then-
// delete) is what makes each nonce single-use even across replicas.
func (s *server) consumeNonce(ctx context.Context, tenant, n string) (bool, error) {
	if n == "" {
		return false, nil
	}
	var rec nonceRec
	err := store.TakeJSON(ctx, s.st, nonceBucket(tenant), n, &rec)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("acme: taking nonce: %w", err)
	}
	return time.Now().Before(rec.Expires), nil
}
