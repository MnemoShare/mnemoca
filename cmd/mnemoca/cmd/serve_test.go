package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
