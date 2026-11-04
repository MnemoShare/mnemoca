package cmd

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/api"
)

func TestServeBootstrapKeyFileWiring(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MNEMOCA_PASSPHRASE", "test")
	reset := func() {
		f := serveCmd.Flags().Lookup("bootstrap-api-key-file")
		if f == nil {
			t.Fatal("serve has no --bootstrap-api-key-file flag")
		}
		_ = f.Value.Set("")
		f.Changed = false
	}
	reset()
	t.Cleanup(reset)

	RootCmd.SetArgs([]string{"init", "--alg", "ml-dsa-65", "--data-dir", dir})
	if err := RootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	serve := func(extra ...string) error {
		RootCmd.SetArgs(append([]string{"serve", "--listen", "127.0.0.1:0", "--data-dir", dir}, extra...))
		return RootCmd.Execute()
	}

	t.Run("flag", func(t *testing.T) {
		err := serve("--bootstrap-api-key-file", bad)
		if err == nil || !strings.Contains(err.Error(), "bootstrap") {
			t.Fatalf("err = %v, want bootstrap key error", err)
		}
	})
	t.Run("env", func(t *testing.T) {
		reset()
		t.Setenv(api.BootstrapKeyEnv, bad)
		err := serve()
		if err == nil || !strings.Contains(err.Error(), "bootstrap") {
			t.Fatalf("err = %v, want bootstrap key error from env", err)
		}
	})
	t.Run("flag overrides env", func(t *testing.T) {
		reset()
		t.Setenv(api.BootstrapKeyEnv, filepath.Join(t.TempDir(), "missing"))
		err := serve("--bootstrap-api-key-file", bad)
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("err = %v, want the flag file (malformed key) to win", err)
		}
	})
}

func TestServeAdoptsBootstrapKeyFromEnvEndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MNEMOCA_PASSPHRASE", "test")
	f := serveCmd.Flags().Lookup("bootstrap-api-key-file")
	_ = f.Value.Set("")
	f.Changed = false

	RootCmd.SetArgs([]string{"init", "--alg", "ml-dsa-65", "--data-dir", dir})
	if err := RootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	key := "mnemoca_0123456789abcdef_" + strings.Repeat("0a", 32)
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(api.BootstrapKeyEnv, keyFile)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	RootCmd.SetArgs([]string{"serve", "--listen", addr, "--data-dir", dir})
	// Cobra keeps the context a subcommand ran with earlier; set it directly.
	serveCmd.SetContext(ctx)
	go func() { done <- RootCmd.ExecuteContext(ctx) }()

	var status int
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/api/v1/tenants", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			status = resp.StatusCode
			_ = resp.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("adopted env key status = %d, want 200", status)
	}
}

func TestServeRejectsUnparseableAllowPrivate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MNEMOCA_PASSPHRASE", "test")
	f := serveCmd.Flags().Lookup("bootstrap-api-key-file")
	_ = f.Value.Set("")
	f.Changed = false
	RootCmd.SetArgs([]string{"init", "--alg", "ml-dsa-65", "--data-dir", dir})
	if err := RootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MNEMOCA_ACME_ALLOW_PRIVATE", "maybe")
	serveCmd.SetContext(context.Background())
	RootCmd.SetArgs([]string{"serve", "--listen", "127.0.0.1:0", "--data-dir", dir})
	err := RootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "MNEMOCA_ACME_ALLOW_PRIVATE") {
		t.Fatalf("err = %v, want a startup error naming MNEMOCA_ACME_ALLOW_PRIVATE", err)
	}
}
