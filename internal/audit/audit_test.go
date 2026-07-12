package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/signer"
)

func testSigner(t *testing.T) (signer.Signer, signer.KeyRef, *signer.Softkey) {
	t.Helper()
	sk, err := signer.NewSoftkey(t.TempDir(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	s, ref, err := sk.Generate(context.Background(), pkix.MLDSA65, "audit")
	if err != nil {
		t.Fatal(err)
	}
	return s, ref, sk
}

func TestChainAppendAndVerify(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testSigner(t)
	path := filepath.Join(t.TempDir(), "audit.log")

	l, err := Open(path, s, "audit-1")
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

	n, err := Verify(path, s.Public())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if n != 7 { // genesis + 5 + checkpoint
		t.Fatalf("records = %d, want 7", n)
	}

	// Reopen appends to the same chain.
	l2, err := Open(path, s, "audit-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Log(ctx, Record{Action: "cert.revoke", Actor: Actor{Type: "operator", ID: "x"}, Object: Object{Type: "cert", ID: "y"}}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(path, s.Public()); err != nil || n != 8 {
		t.Fatalf("after reopen: n=%d err=%v", n, err)
	}
}

func TestTamperDetection(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testSigner(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(path, s, "audit-1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(ctx, Record{Action: "cert.issue", Actor: Actor{Type: "a", ID: "b"}, Object: Object{Type: "cert", ID: "c"}, Detail: map[string]string{"cn": "victim"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Modify a field in the middle record.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(data)
	var rec map[string]any
	if err := json.Unmarshal(lines[2], &rec); err != nil {
		t.Fatal(err)
	}
	rec["detail"] = map[string]string{"cn": "attacker"}
	modified, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	lines[2] = modified
	if err := os.WriteFile(path, joinLines(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(path, s.Public()); err == nil {
		t.Fatal("tampered log verified")
	}

	// Truncation (dropping the last record) breaks nothing structurally but
	// checkpoint comparison catches it; dropping a middle record breaks seq.
	if err := os.WriteFile(path, joinLines(append(lines[:1], lines[2:]...)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, s.Public()); err == nil {
		t.Fatal("log with removed record verified")
	}
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, append([]byte(nil), data[start:i]...))
			start = i + 1
		}
	}
	return out
}

func joinLines(lines [][]byte) []byte {
	var out []byte
	for _, l := range lines {
		out = append(out, l...)
		out = append(out, '\n')
	}
	return out
}
