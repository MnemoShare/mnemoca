package ca

import (
	"context"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"path/filepath"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store/storetest"
)

func testEnv(t *testing.T) *Env {
	t.Helper()
	env, err := OpenEnv(t.TempDir(), []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Close() })
	return env
}

// testEnvMongo opens a mongo-backed env against a disposable test database,
// skipping when MongoDB is unavailable.
func testEnvMongo(t *testing.T) *Env {
	t.Helper()
	uri, dbName := storetest.TempDB(t)
	env, err := OpenEnvConfig(context.Background(), Config{
		Dir:        t.TempDir(),
		Passphrase: []byte("test"),
		DB:         "mongo",
		MongoURI:   uri,
		MongoDB:    dbName,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Close() })
	return env
}

// verifyAuditChain replays the env's audit chain (file or store) with only
// the audit public key and returns the record count.
func verifyAuditChain(t *testing.T, env *Env, auditPubPEM []byte) int {
	t.Helper()
	pub, err := pkix.ParsePublicKeyPEM(auditPubPEM)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if env.DB == "mongo" {
		n, err = audit.VerifyStore(context.Background(), env.Store, pub)
	} else {
		n, err = audit.Verify(filepath.Join(env.Dir, "audit.log"), pub)
	}
	if err != nil {
		t.Fatalf("audit verify: %v", err)
	}
	return n
}

func testCSR(t *testing.T, cn string, alg pkix.Algorithm) *pkix.CertificateRequest {
	t.Helper()
	key, err := pkix.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pkix.CreateCertificateRequest(&x509.CertificateRequest{
		Subject:  stdpkix.Name{CommonName: cn},
		DNSNames: []string{cn + ".example.com"},
	}, key, alg)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// TestEndToEnd exercises init → tenant → issue → revoke → CRL → audit verify
// on a hybrid (ML-DSA-87 + ECDSA P-384) root, on the default bolt backend.
func TestEndToEnd(t *testing.T) {
	endToEnd(t, testEnv(t))
}

// TestEndToEndMongo runs the same flow with the MongoDB store, storekey
// backend, and store-backed audit chain (ADR-0010).
func TestEndToEndMongo(t *testing.T) {
	endToEnd(t, testEnvMongo(t))
}

func endToEnd(t *testing.T, env *Env) {
	ctx := context.Background()
	actor := audit.Actor{Type: "operator", ID: "test"}

	info, err := env.Init(ctx, InitOptions{
		Name:    "Test Root",
		Alg:     pkix.MLDSA87,
		PairAlg: pkix.ECDSAP384,
		Actor:   actor,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if info.PairAlg != pkix.ECDSAP384 {
		t.Fatalf("pair alg = %q", info.PairAlg)
	}

	tenant, err := env.Manager.CreateTenant(ctx, "acme-corp", "ACME Corp", pkix.MLDSA65, true, actor)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if tenant.PairAlg != pkix.ECDSAP384 {
		t.Fatalf("tenant pair alg = %q", tenant.PairAlg)
	}

	// Issue on both chains from one ECDSA-keyed CSR.
	csr := testCSR(t, "mtls-client", pkix.ECDSAP256)
	issued, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "acme-corp", CSR: csr, Chain: ChainBoth, Actor: actor,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(issued) != 2 {
		t.Fatalf("issued %d certs, want 2", len(issued))
	}
	for _, iss := range issued {
		if err := pkix.VerifyChain(iss.Path, time.Now()); err != nil {
			t.Fatalf("chain %s: %v", iss.Chain, err)
		}
	}
	if issued[0].Cert.Algorithm != pkix.MLDSA65 {
		t.Fatalf("primary leaf signed with %q, want ml-dsa-65", issued[0].Cert.Algorithm)
	}
	if issued[1].Cert.Algorithm != pkix.ECDSAP384 {
		t.Fatalf("pair leaf signed with %q, want ecdsa-p384", issued[1].Cert.Algorithm)
	}

	// Revoke the primary-chain cert and check the CRL.
	serial := issued[0].Cert.X509.SerialNumber.String()
	if err := env.Manager.Revoke(ctx, "acme-corp", serial, 1, actor); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	crl, err := env.Manager.BuildCRL(ctx, "acme-corp", ChainPrimary, actor)
	if err != nil {
		t.Fatalf("BuildCRL: %v", err)
	}
	if len(crl.Revoked) != 1 || crl.Revoked[0].SerialNumber.String() != serial {
		t.Fatalf("CRL revoked = %+v", crl.Revoked)
	}
	issuingCert, err := pkix.ParseCertificatePEM(tenant.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(issuingCert); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}

	// Full audit chain must verify with only the audit public key.
	if n := verifyAuditChain(t, env, info.AuditPubPEM); n < 6 {
		// genesis, ca.init, tenant.create, 2x cert.issue, cert.revoke, crl.publish
		t.Fatalf("audit records = %d", n)
	}

	// Profile enforcement: composite CSR without opt-in is rejected.
	compCSR := testCSR(t, "composite-client", pkix.CompositeMLDSA65ECDSAP256)
	if _, err := env.Manager.Issue(ctx, IssueRequest{Tenant: "acme-corp", CSR: compCSR, Actor: actor}); err == nil {
		t.Fatal("composite CSR accepted without experimental opt-in")
	}
	if _, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "acme-corp", CSR: compCSR, ExperimentalComposite: true, Actor: actor,
	}); err != nil {
		t.Fatalf("composite issue with opt-in: %v", err)
	}
}

// TestReopen verifies persistence: a reopened env serves the same tenants and
// keys and appends to the same audit chain.
func TestReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	actor := audit.Actor{Type: "operator", ID: "test"}

	env, err := OpenEnv(dir, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Init(ctx, InitOptions{Alg: pkix.MLDSA65, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.CreateTenant(ctx, "t1", "", "", false, actor); err != nil {
		t.Fatal(err)
	}
	_ = env.Close()

	env2, err := OpenEnv(dir, []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = env2.Close() }()
	csr := testCSR(t, "after-reopen", pkix.MLDSA44)
	issued, err := env2.Manager.Issue(ctx, IssueRequest{Tenant: "t1", CSR: csr, Actor: actor})
	if err != nil {
		t.Fatalf("Issue after reopen: %v", err)
	}
	if err := pkix.VerifyChain(issued[0].Path, time.Now()); err != nil {
		t.Fatal(err)
	}

	info, err := env2.Manager.Root(ctx)
	if err != nil {
		t.Fatal(err)
	}
	verifyAuditChain(t, env2, info.AuditPubPEM)
}
