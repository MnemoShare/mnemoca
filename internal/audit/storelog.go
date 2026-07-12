package audit

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/signer"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// Store bucket layout (ADR-0010): records keyed by zero-padded sequence
// number so store iteration order is chain order; the chain head is a single
// CAS-advanced document that serializes appends across replicas.
var (
	auditRecordsBucket = []string{"audit", "records"}
	auditMetaBucket    = []string{"audit", "meta"}
)

const headKey = "head"

// chainHead is the CAS-advanced head document at audit/meta/head.
type chainHead struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// seqKey renders a sequence number as a sortable record key.
func seqKey(seq uint64) string { return fmt.Sprintf("%020d", seq) }

// StoreLog is the store-backed ChainLogger for HA deployments: same records,
// hash chain, and signatures as the file Log, persisted as store documents.
// Appends serialize via compare-and-swap on the head document, so any number
// of replicas share one chain (losers retry inside store.Update). A crash
// between the head advance and the record write leaves a sequence gap that
// VerifyStore reports precisely — fail-loud, never silent (ADR-0010).
type StoreLog struct {
	st     store.Store
	signer signer.Signer
	keyID  string
}

var _ ChainLogger = (*StoreLog)(nil)

// OpenStore opens (creating the genesis record if needed) the store-backed
// audit log over st, signing with sig. keyID names the audit key.
func OpenStore(ctx context.Context, st store.Store, sig signer.Signer, keyID string) (*StoreLog, error) {
	if err := checkAuditAlg(sig); err != nil {
		return nil, err
	}
	l := &StoreLog{st: st, signer: sig, keyID: keyID}
	if err := l.ensureGenesis(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

// ensureGenesis creates the head document and genesis record exactly once,
// even when several replicas open the log concurrently: the head write is an
// atomic create, and only the replica that created it writes the record.
func (l *StoreLog) ensureGenesis(ctx context.Context) error {
	var genesis *Record
	err := l.st.Update(ctx, auditMetaBucket, headKey, true, func(data []byte) ([]byte, error) {
		if data != nil {
			return data, nil // chain already exists; keep it
		}
		// Genesis: random anchor makes chain truncation-to-empty detectable
		// when compared against the anchor recorded at ca.init.
		anchor := make([]byte, 32)
		if _, err := rand.Read(anchor); err != nil {
			return nil, err
		}
		rec := Record{
			Seq:      1,
			Time:     time.Now().UTC(),
			Action:   "audit.genesis",
			Actor:    Actor{Type: "system", ID: "mnemoca"},
			Object:   Object{Type: "audit", ID: "genesis"},
			PrevHash: hex.EncodeToString(anchor),
			KeyID:    l.keyID,
		}
		if err := sealRecord(&rec, l.signer); err != nil {
			return nil, err
		}
		genesis = &rec
		return json.Marshal(chainHead{Seq: rec.Seq, Hash: rec.Hash})
	})
	if err != nil {
		return fmt.Errorf("audit: initializing store chain: %w", err)
	}
	if genesis != nil {
		if err := store.PutJSON(ctx, l.st, auditRecordsBucket, seqKey(genesis.Seq), genesis); err != nil {
			return fmt.Errorf("audit: writing genesis record: %w", err)
		}
	}
	return nil
}

// Log appends a record: claims the next sequence number by CAS on the head
// document (recomputing chain fields on every retry), then writes the record.
func (l *StoreLog) Log(ctx context.Context, rec Record) error {
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	rec.KeyID = l.keyID

	var sealed Record
	err := store.UpdateJSON(ctx, l.st, auditMetaBucket, headKey, false, func(h *chainHead) error {
		// Recomputed on every optimistic retry against the fresh head.
		sealed = rec
		sealed.Seq = h.Seq + 1
		sealed.PrevHash = h.Hash
		if err := sealRecord(&sealed, l.signer); err != nil {
			return err
		}
		h.Seq = sealed.Seq
		h.Hash = sealed.Hash
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("audit: store chain not initialized")
	}
	if err != nil {
		return fmt.Errorf("audit: advancing chain head: %w", err)
	}
	if err := store.PutJSON(ctx, l.st, auditRecordsBucket, seqKey(sealed.Seq), &sealed); err != nil {
		return fmt.Errorf("audit: appending record %d: %w", sealed.Seq, err)
	}
	return nil
}

// Checkpoint appends a signed checkpoint record binding the current sequence
// number and head hash, making later truncation detectable.
func (l *StoreLog) Checkpoint(ctx context.Context) error {
	var h chainHead
	if err := store.GetJSON(ctx, l.st, auditMetaBucket, headKey, &h); err != nil {
		return fmt.Errorf("audit: reading chain head: %w", err)
	}
	return l.Log(ctx, Record{
		Action: "audit.checkpoint",
		Actor:  Actor{Type: "system", ID: "mnemoca"},
		Object: Object{Type: "audit", ID: "checkpoint"},
		Detail: map[string]string{
			"checkpoint_seq":  fmt.Sprint(h.Seq),
			"checkpoint_head": h.Hash,
		},
	})
}

// Close releases nothing: the underlying store is owned and closed by the
// environment.
func (l *StoreLog) Close() error { return nil }

// VerifyStore replays the store-backed chain, checking sequence continuity,
// hash linkage, and every signature against pub, and finally that the head
// document matches the last record (a mismatch pinpoints a crash between
// head-advance and record-write). It returns the number of verified records.
func VerifyStore(ctx context.Context, st store.Store, pub crypto.PublicKey) (int, error) {
	alg, err := pkix.AlgorithmForKey(pub)
	if err != nil {
		return 0, err
	}
	var count int
	var prevHash string
	var prevSeq uint64
	err = store.ForEachJSON(ctx, st, auditRecordsBucket, func(_ string, rec Record) error {
		if err := verifyRecord(rec, pub, alg, prevHash, prevSeq, count+1); err != nil {
			return err
		}
		prevHash = rec.Hash
		prevSeq = rec.Seq
		count++
		return nil
	})
	if err != nil {
		return count, err
	}
	var h chainHead
	if err := store.GetJSON(ctx, st, auditMetaBucket, headKey, &h); err != nil {
		if errors.Is(err, store.ErrNotFound) && count == 0 {
			return 0, fmt.Errorf("audit: store chain not initialized")
		}
		return count, fmt.Errorf("audit: reading chain head: %w", err)
	}
	if h.Seq != prevSeq || h.Hash != prevHash {
		return count, fmt.Errorf("audit: head (seq %d) does not match last record (seq %d): missing or extra record(s)", h.Seq, prevSeq)
	}
	return count, nil
}
