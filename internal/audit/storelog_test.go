package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/store"
)

func testStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestStoreChainAppendAndVerify(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testSigner(t)
	st := testStore(t)

	l, err := OpenStore(ctx, st, s, "audit-1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Log(ctx, Record{
			Tenant: "t1",
			Actor:  Actor{Type: "operator", ID: "test"},
			Action: "cert.issue",
			Object: Object{Type: "cert", ID: "serial"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	n, err := VerifyStore(ctx, st, s.Public())
	if err != nil {
		t.Fatalf("VerifyStore: %v", err)
	}
	if n != 7 { // genesis + 5 + checkpoint
		t.Fatalf("records = %d, want 7", n)
	}

	// Reopening appends to the same chain (no second genesis).
	l2, err := OpenStore(ctx, st, s, "audit-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Log(ctx, Record{Action: "cert.revoke", Actor: Actor{Type: "operator", ID: "x"}, Object: Object{Type: "cert", ID: "y"}}); err != nil {
		t.Fatal(err)
	}
	if n, err := VerifyStore(ctx, st, s.Public()); err != nil || n != 8 {
		t.Fatalf("after reopen: n=%d err=%v", n, err)
	}
}

func TestStoreTamperDetection(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testSigner(t)
	st := testStore(t)

	l, err := OpenStore(ctx, st, s, "audit-1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(ctx, Record{Action: "cert.issue", Actor: Actor{Type: "a", ID: "b"}, Object: Object{Type: "cert", ID: "c"}, Detail: map[string]string{"cn": "victim"}}); err != nil {
			t.Fatal(err)
		}
	}

	// Mutate a middle record document in place via the store.
	key := fmt.Sprintf("%020d", 2)
	var rec Record
	if err := store.GetJSON(ctx, st, auditRecordsBucket, key, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Detail = map[string]string{"cn": "attacker"}
	if err := store.PutJSON(ctx, st, auditRecordsBucket, key, &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStore(ctx, st, s.Public()); err == nil {
		t.Fatal("tampered store chain verified")
	}

	// Deleting a record leaves a sequence gap that verification reports.
	if err := st.Delete(ctx, auditRecordsBucket, key); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStore(ctx, st, s.Public()); err == nil {
		t.Fatal("store chain with a removed record verified")
	}
}

// TestStoreHeadRecordMismatch simulates a crash between head-advance and
// record-write: the head claims a sequence number with no record behind it.
func TestStoreHeadRecordMismatch(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testSigner(t)
	st := testStore(t)

	l, err := OpenStore(ctx, st, s, "audit-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(ctx, Record{Action: "cert.issue", Actor: Actor{Type: "a", ID: "b"}, Object: Object{Type: "cert", ID: "c"}}); err != nil {
		t.Fatal(err)
	}
	// Advance the head without writing the record.
	err = store.UpdateJSON(ctx, st, auditMetaBucket, headKey, false, func(h *chainHead) error {
		h.Seq++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyStore(ctx, st, s.Public()); err == nil {
		t.Fatal("chain with a head/record gap verified")
	}
}

func TestStoreConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testSigner(t)
	st := testStore(t)

	l, err := OpenStore(ctx, st, s, "audit-1")
	if err != nil {
		t.Fatal(err)
	}

	const goroutines, perGoroutine = 10, 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				errs <- l.Log(ctx, Record{
					Action: "cert.issue",
					Actor:  Actor{Type: "operator", ID: fmt.Sprintf("g%d", g)},
					Object: Object{Type: "cert", ID: fmt.Sprintf("%d-%d", g, i)},
				})
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	// The chain must verify end to end: genesis + 100 records, no gaps, no
	// forks, head matching the last record.
	n, err := VerifyStore(ctx, st, s.Public())
	if err != nil {
		t.Fatalf("VerifyStore after concurrent appends: %v", err)
	}
	if n != goroutines*perGoroutine+1 {
		t.Fatalf("records = %d, want %d", n, goroutines*perGoroutine+1)
	}
}
