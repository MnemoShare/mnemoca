package acme

import (
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
func (s *server) issueNonce(w http.ResponseWriter, tenant string) error {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Errorf("acme: generating nonce: %w", err)
	}
	n := rawB64(b[:])
	if err := s.st.PutJSON(nonceBucket(tenant), n, nonceRec{Expires: time.Now().Add(nonceTTL)}); err != nil {
		return fmt.Errorf("acme: storing nonce: %w", err)
	}
	w.Header().Set("Replay-Nonce", n)
	w.Header().Set("Cache-Control", "no-store")
	return nil
}

// consumeNonce deletes n and reports whether it existed and was unexpired.
// Expired nonces are deleted on sight.
func (s *server) consumeNonce(tenant, n string) (bool, error) {
	if n == "" {
		return false, nil
	}
	var rec nonceRec
	err := s.st.GetJSON(nonceBucket(tenant), n, &rec)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("acme: loading nonce: %w", err)
	}
	if err := s.st.Delete(nonceBucket(tenant), n); err != nil {
		return false, fmt.Errorf("acme: deleting nonce: %w", err)
	}
	return time.Now().Before(rec.Expires), nil
}
