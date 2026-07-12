package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/store"
	"github.com/mnemoshare/mnemoca/internal/store/storetest"
)

// backends lists the Store implementations under test; every case in the
// conformance suite runs against all of them (ADR-0010: behavior cannot
// drift unnoticed).
var backends = []struct {
	name string
	open func(t *testing.T) store.Store
}{
	{"bolt", newBoltStore},
	{"mongo", newMongoStore},
}

func newBoltStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newMongoStore(t *testing.T) store.Store {
	t.Helper()
	uri, dbName := storetest.TempDB(t)
	s, err := store.OpenMongo(context.Background(), uri, dbName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// forEachBackend runs fn as a subtest per backend.
func forEachBackend(t *testing.T, fn func(t *testing.T, s store.Store)) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			fn(t, b.open(t))
		})
	}
}

func TestPutGetDelete(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		path := []string{"certs", "t1"}

		if _, err := s.Get(ctx, path, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get missing = %v, want ErrNotFound", err)
		}
		if err := s.Put(ctx, path, "k1", []byte(`{"a":1}`)); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, path, "k1")
		if err != nil || string(got) != `{"a":1}` {
			t.Fatalf("Get = %q, %v", got, err)
		}
		// Overwrite.
		if err := s.Put(ctx, path, "k1", []byte(`{"a":2}`)); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Get(ctx, path, "k1"); string(got) != `{"a":2}` {
			t.Fatalf("after overwrite Get = %q", got)
		}
		// Same key under a different path is a different document.
		if _, err := s.Get(ctx, []string{"certs", "t2"}, "k1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross-path Get = %v, want ErrNotFound", err)
		}
		if err := s.Delete(ctx, path, "k1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, path, "k1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
		}
		// Deleting a missing key (and a missing path) is not an error.
		if err := s.Delete(ctx, path, "k1"); err != nil {
			t.Fatalf("Delete missing key = %v", err)
		}
		if err := s.Delete(ctx, []string{"nope"}, "k1"); err != nil {
			t.Fatalf("Delete missing path = %v", err)
		}
	})
}

func TestTakeAtomicity(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		path := []string{"acme", "t1", "nonces"}

		if _, err := s.Take(ctx, path, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Take missing = %v, want ErrNotFound", err)
		}
		if err := s.Put(ctx, path, "n1", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}

		// Exactly one of N concurrent takers wins.
		const takers = 10
		var wg sync.WaitGroup
		wins := make(chan []byte, takers)
		for i := 0; i < takers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				data, err := s.Take(ctx, path, "n1")
				if err == nil {
					wins <- data
				} else if !errors.Is(err, store.ErrNotFound) {
					t.Errorf("Take: %v", err)
				}
			}()
		}
		wg.Wait()
		close(wins)
		var count int
		for range wins {
			count++
		}
		if count != 1 {
			t.Fatalf("%d takers succeeded, want exactly 1", count)
		}
		if _, err := s.Get(ctx, path, "n1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get after Take = %v, want ErrNotFound", err)
		}
	})
}

func TestForEachOrder(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		path := []string{"audit", "records"}

		// ForEach over a missing path visits nothing.
		if err := s.ForEach(ctx, path, func(string, []byte) error {
			t.Fatal("visited a document in an empty path")
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		// Insert out of order; expect key-ordered iteration.
		for _, k := range []string{"00000000000000000003", "00000000000000000001", "00000000000000000002"} {
			if err := s.Put(ctx, path, k, []byte(`"`+k+`"`)); err != nil {
				t.Fatal(err)
			}
		}
		var keys []string
		err := s.ForEach(ctx, path, func(key string, data []byte) error {
			keys = append(keys, key)
			if string(data) != `"`+key+`"` {
				t.Fatalf("key %s carries data %q", key, data)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"00000000000000000001", "00000000000000000002", "00000000000000000003"}
		if len(keys) != len(want) {
			t.Fatalf("keys = %v, want %v", keys, want)
		}
		for i := range want {
			if keys[i] != want[i] {
				t.Fatalf("keys = %v, want %v (out of order)", keys, want)
			}
		}

		// Callback errors propagate.
		sentinel := errors.New("stop")
		if err := s.ForEach(ctx, path, func(string, []byte) error { return sentinel }); !errors.Is(err, sentinel) {
			t.Fatalf("ForEach error = %v, want sentinel", err)
		}
	})
}

func TestUpdate(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		path := []string{"meta"}

		// Absent + no create → ErrNotFound.
		err := s.Update(ctx, path, "counter", false, func([]byte) ([]byte, error) { return []byte("x"), nil })
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Update absent = %v, want ErrNotFound", err)
		}

		// Absent + create: fn sees nil.
		err = s.Update(ctx, path, "counter", true, func(data []byte) ([]byte, error) {
			if data != nil {
				t.Fatalf("create-update saw existing data %q", data)
			}
			return []byte(`{"n":1}`), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Get(ctx, path, "counter"); string(got) != `{"n":1}` {
			t.Fatalf("after create-update = %q", got)
		}

		// fn errors abort without modifying.
		sentinel := errors.New("nope")
		err = s.Update(ctx, path, "counter", false, func([]byte) ([]byte, error) { return nil, sentinel })
		if !errors.Is(err, sentinel) {
			t.Fatalf("Update fn error = %v, want sentinel", err)
		}
		if got, _ := s.Get(ctx, path, "counter"); string(got) != `{"n":1}` {
			t.Fatalf("after failed update = %q", got)
		}
	})
}

type counterDoc struct {
	N int `json:"n"`
}

func TestUpdateConcurrency(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		path := []string{"meta"}
		const writers = 20

		var wg sync.WaitGroup
		errs := make(chan error, writers)
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- store.UpdateJSON(ctx, s, path, "shared", true, func(v *counterDoc) error {
					v.N++
					return nil
				})
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		var v counterDoc
		if err := store.GetJSON(ctx, s, path, "shared", &v); err != nil {
			t.Fatal(err)
		}
		if v.N != writers {
			t.Fatalf("counter = %d, want %d (lost updates)", v.N, writers)
		}
	})
}

func TestNextSeq(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		path := []string{"crl", "t1"}

		// Strictly monotonic, starting at 1.
		var prev uint64
		for i := 0; i < 5; i++ {
			n, err := s.NextSeq(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if n != prev+1 {
				t.Fatalf("NextSeq = %d after %d", n, prev)
			}
			prev = n
		}

		// Independent per path.
		n, err := s.NextSeq(ctx, []string{"crl", "t2"})
		if err != nil || n != 1 {
			t.Fatalf("other-path NextSeq = %d, %v; want 1", n, err)
		}

		// Concurrent callers get distinct values.
		const callers = 20
		var wg sync.WaitGroup
		got := make(chan uint64, callers)
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := s.NextSeq(ctx, path)
				if err != nil {
					t.Errorf("NextSeq: %v", err)
					return
				}
				got <- n
			}()
		}
		wg.Wait()
		close(got)
		seen := make(map[uint64]bool)
		for n := range got {
			if seen[n] {
				t.Fatalf("NextSeq returned %d twice", n)
			}
			seen[n] = true
		}
		if len(seen) != callers {
			t.Fatalf("got %d distinct values, want %d", len(seen), callers)
		}
	})
}

func TestJSONHelpers(t *testing.T) {
	forEachBackend(t, func(t *testing.T, s store.Store) {
		ctx := context.Background()
		path := []string{"tenants"}
		type doc struct {
			Name string `json:"name"`
		}

		if err := store.PutJSON(ctx, s, path, "a", doc{Name: "alpha"}); err != nil {
			t.Fatal(err)
		}
		if err := store.PutJSON(ctx, s, path, "b", doc{Name: "beta"}); err != nil {
			t.Fatal(err)
		}
		var d doc
		if err := store.GetJSON(ctx, s, path, "a", &d); err != nil || d.Name != "alpha" {
			t.Fatalf("GetJSON = %+v, %v", d, err)
		}
		var names []string
		if err := store.ForEachJSON(ctx, s, path, func(_ string, v doc) error {
			names = append(names, v.Name)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(names) != "[alpha beta]" {
			t.Fatalf("names = %v", names)
		}
		if err := store.TakeJSON(ctx, s, path, "b", &d); err != nil || d.Name != "beta" {
			t.Fatalf("TakeJSON = %+v, %v", d, err)
		}
		if err := store.TakeJSON(ctx, s, path, "b", &d); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("second TakeJSON = %v, want ErrNotFound", err)
		}
	})
}
