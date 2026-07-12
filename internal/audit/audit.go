// Package audit implements MnemoCA's tamper-evident audit log (ADR-0008):
// append-only JSONL, each record hash-chained to its predecessor and signed
// with a dedicated audit key. Verification is offline given only the audit
// public key.
package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/signer"
)

// Actor identifies who performed an action.
type Actor struct {
	Type string `json:"type"` // "operator" | "apikey" | "acme" | "system"
	ID   string `json:"id"`
	IP   string `json:"ip,omitempty"`
}

// Object identifies what was acted on.
type Object struct {
	Type string `json:"type"` // "ca" | "key" | "cert" | "crl" | "tenant" | "acme-account" | ...
	ID   string `json:"id"`
}

// Record is one audit event. Hash and Sig are computed by the log.
type Record struct {
	Seq      uint64            `json:"seq"`
	Time     time.Time         `json:"time"`
	Tenant   string            `json:"tenant,omitempty"`
	Actor    Actor             `json:"actor"`
	Action   string            `json:"action"`
	Object   Object            `json:"object"`
	Detail   map[string]string `json:"detail,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
	KeyID    string            `json:"key_id"`
	Sig      []byte            `json:"sig"`
}

// Logger is the interface consumed by the CA engine, ACME server, and API.
type Logger interface {
	// Log appends the record durably before returning (write-ahead auditing:
	// issuance does not complete until its record is on disk).
	Log(ctx context.Context, rec Record) error
}

// ChainLogger is a production audit log: a Logger that can also write
// checkpoint records and be closed. Implemented by the file-backed Log and
// the store-backed StoreLog (ADR-0010).
type ChainLogger interface {
	Logger
	Checkpoint(ctx context.Context) error
	Close() error
}

// Nop discards records (tests only).
type Nop struct{}

func (Nop) Log(context.Context, Record) error { return nil }

// Log is the production Logger: hash-chained, signed JSONL.
type Log struct {
	mu     sync.Mutex
	f      *os.File
	signer signer.Signer
	keyID  string
	seq    uint64
	head   string // hex hash of last record
}

// Open opens (creating if needed) the audit log at path, signing with sig.
// keyID names the audit key (for rotation). If the file is non-empty, the
// chain head is recovered from the last record.
func Open(path string, sig signer.Signer, keyID string) (*Log, error) {
	if err := checkAuditAlg(sig); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{f: f, signer: sig, keyID: keyID}

	last, err := lastRecord(path)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if last == nil {
		// Genesis: random anchor makes chain truncation-to-empty detectable
		// when compared against the anchor recorded at ca.init.
		anchor := make([]byte, 32)
		if _, err := rand.Read(anchor); err != nil {
			_ = f.Close()
			return nil, err
		}
		l.head = hex.EncodeToString(anchor)
		if err := l.Log(context.Background(), Record{
			Action: "audit.genesis",
			Actor:  Actor{Type: "system", ID: "mnemoca"},
			Object: Object{Type: "audit", ID: "genesis"},
		}); err != nil {
			_ = f.Close()
			return nil, err
		}
	} else {
		l.seq = last.Seq
		l.head = last.Hash
	}
	return l, nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// canonical returns the deterministic byte form of rec with Hash and Sig
// cleared; struct field order makes encoding/json deterministic.
func canonical(rec Record) ([]byte, error) {
	rec.Hash = ""
	rec.Sig = nil
	return json.Marshal(rec)
}

// checkAuditAlg rejects digest-based signers (ECDSA), which would diverge
// between Log and Verify; ADR-0008 specifies a message-signing audit key
// (ML-DSA-65).
func checkAuditAlg(sig signer.Signer) error {
	info, err := pkix.Lookup(sig.Algorithm())
	if err != nil {
		return err
	}
	if info.Hash != 0 {
		return fmt.Errorf("audit: audit key must use a message-signing algorithm, got %q", sig.Algorithm())
	}
	return nil
}

// chainHash computes the record's chained hash: SHA-256(prev_hash || canonical).
func chainHash(rec Record) ([]byte, error) {
	canon, err := canonical(rec)
	if err != nil {
		return nil, err
	}
	prev, err := hex.DecodeString(rec.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("audit: bad prev_hash: %w", err)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(canon)
	return h.Sum(nil), nil
}

// sealRecord computes rec's chained hash and signs it. Seq, Time, PrevHash,
// and KeyID must already be set. Shared by the file and store logs.
func sealRecord(rec *Record, sig signer.Signer) error {
	sum, err := chainHash(*rec)
	if err != nil {
		return fmt.Errorf("audit: corrupt chain head: %w", err)
	}
	rec.Hash = hex.EncodeToString(sum)
	s, err := sig.Sign(rand.Reader, sum, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("audit: signing record: %w", err)
	}
	rec.Sig = s
	return nil
}

// verifyRecord replays one record against the previous chain state: sequence
// continuity, chain linkage, hash recomputation, and signature. Shared by the
// file and store verifiers. n is the 1-based record position for error text.
func verifyRecord(rec Record, pub crypto.PublicKey, alg pkix.Algorithm, prevHash string, prevSeq uint64, n int) error {
	if rec.Seq != prevSeq+1 {
		return fmt.Errorf("audit: record %d: sequence gap (%d after %d)", n, rec.Seq, prevSeq)
	}
	if prevHash != "" && rec.PrevHash != prevHash {
		return fmt.Errorf("audit: record %d: chain break", n)
	}
	sum, err := chainHash(rec)
	if err != nil {
		return fmt.Errorf("audit: record %d: %w", n, err)
	}
	if hex.EncodeToString(sum) != rec.Hash {
		return fmt.Errorf("audit: record %d: hash mismatch (tampered)", n)
	}
	if err := pkix.VerifyRawSignature(pub, alg, sum, rec.Sig); err != nil {
		return fmt.Errorf("audit: record %d: signature invalid: %w", n, err)
	}
	return nil
}

// Log appends a record: assigns seq/time/chain fields, hashes, signs, writes,
// and fsyncs before returning.
func (l *Log) Log(_ context.Context, rec Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	rec.Seq = l.seq
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	rec.PrevHash = l.head
	rec.KeyID = l.keyID

	if err := sealRecord(&rec, l.signer); err != nil {
		return err
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: appending record: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("audit: fsync: %w", err)
	}
	l.head = rec.Hash
	return nil
}

// Checkpoint appends a signed checkpoint record binding the current sequence
// number and head hash, making later truncation detectable.
func (l *Log) Checkpoint(ctx context.Context) error {
	l.mu.Lock()
	seq, head := l.seq, l.head
	l.mu.Unlock()
	return l.Log(ctx, Record{
		Action: "audit.checkpoint",
		Actor:  Actor{Type: "system", ID: "mnemoca"},
		Object: Object{Type: "audit", ID: "checkpoint"},
		Detail: map[string]string{
			"checkpoint_seq":  fmt.Sprint(seq),
			"checkpoint_head": head,
		},
	})
}

// Verify replays the log at path, checking the hash chain and every
// signature against pub (the audit public key). It returns the number of
// verified records.
func Verify(path string, pub crypto.PublicKey) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	alg, err := pkix.AlgorithmForKey(pub)
	if err != nil {
		return 0, err
	}

	dec := json.NewDecoder(f)
	var count int
	var prevHash string
	var prevSeq uint64
	for dec.More() {
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			return count, fmt.Errorf("audit: record %d: corrupt JSON: %w", count+1, err)
		}
		if err := verifyRecord(rec, pub, alg, prevHash, prevSeq, count+1); err != nil {
			return count, err
		}
		prevHash = rec.Hash
		prevSeq = rec.Seq
		count++
	}
	return count, nil
}

// lastRecord returns the final record in the file, or nil if empty.
func lastRecord(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var last *Record
	for dec.More() {
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("audit: existing log corrupt: %w", err)
		}
		last = &rec
	}
	return last, nil
}
