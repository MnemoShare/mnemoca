package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// TestCLIWiring runs init → keygen → csr → tenant create → issue through the
// cobra command tree against a temp data directory.
func TestCLIWiring(t *testing.T) {
	dir := t.TempDir()
	work := t.TempDir()
	t.Setenv("MNEMOCA_PASSPHRASE", "test")

	run := func(args ...string) {
		t.Helper()
		RootCmd.SetArgs(append(args, "--data-dir", dir))
		if err := RootCmd.Execute(); err != nil {
			t.Fatalf("mnemoca %v: %v", args, err)
		}
	}

	run("init", "--alg", "ml-dsa-65", "--name", "Test Root")
	if _, err := os.Stat(filepath.Join(dir, "root.pem")); err != nil {
		t.Fatalf("root.pem not written: %v", err)
	}

	keyPath := filepath.Join(work, "key.pem")
	run("keygen", "--alg", "ecdsa-p256", "-o", keyPath)

	csrPath := filepath.Join(work, "csr.pem")
	run("csr", "--key", keyPath, "--cn", "cli-client", "--dns", "cli.example.com", "-o", csrPath)
	csrData, err := os.ReadFile(csrPath)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pkix.ParseCSRPEM(csrData)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "cli-client" || csr.PublicKeyAlgorithm != pkix.ECDSAP256 {
		t.Fatalf("csr = CN %q, key alg %q", csr.Subject.CommonName, csr.PublicKeyAlgorithm)
	}

	run("tenant", "create", "t1", "--name", "Tenant One")
	run("tenant", "list")

	certPath := filepath.Join(work, "cert.pem")
	run("issue", "--tenant", "t1", "--csr", csrPath, "--validity", "24h", "-o", certPath)
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := pkix.ParseChainPEM(certData)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("issued chain length = %d, want 3", len(chain))
	}
	if err := pkix.VerifyChain(chain, time.Now()); err != nil {
		t.Fatalf("issued chain: %v", err)
	}
	if chain[0].X509.Subject.CommonName != "cli-client" {
		t.Fatalf("leaf CN = %q", chain[0].X509.Subject.CommonName)
	}

	run("certs", "--tenant", "t1")
	run("inspect", certPath)
	run("inspect", csrPath)
	run("audit", "verify")
	run("version")
}
