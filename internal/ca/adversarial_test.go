package ca

// Adversarial / negative-path coverage for the CA engine. Every case asserts
// rejection of an unsafe request.

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
)

var advActor = audit.Actor{Type: "operator", ID: "adversary-test"}

// initEnvWithTenant returns an initialized non-hybrid env with tenant "t1".
func initEnvWithTenant(t *testing.T) (*Env, context.Context) {
	t.Helper()
	env := testEnv(t)
	ctx := context.Background()
	if _, err := env.Init(ctx, InitOptions{Alg: pkix.MLDSA65, Actor: advActor}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.CreateTenant(ctx, "t1", "", "", false, advActor); err != nil {
		t.Fatal(err)
	}
	return env, ctx
}

// TestIssueInvalidCSRSignature rejects a CSR whose self-signature no longer
// matches its (tampered) contents.
func TestIssueInvalidCSRSignature(t *testing.T) {
	env, ctx := initEnvWithTenant(t)
	csr := testCSR(t, "badsig", pkix.ECDSAP256)

	// Tamper a byte inside the SAN dNSName after signing, then re-parse.
	raw := append([]byte(nil), csr.Raw...)
	idx := bytes.Index(raw, []byte("example"))
	if idx < 0 {
		t.Fatal("could not locate SAN to tamper")
	}
	raw[idx] ^= 0xff
	bad, err := pkix.ParseCertificateRequest(raw)
	if err != nil {
		t.Fatalf("tampered CSR should still parse: %v", err)
	}

	if _, err := env.Manager.Issue(ctx, IssueRequest{Tenant: "t1", CSR: bad, Actor: advActor}); err == nil {
		t.Fatal("issuance accepted a CSR with an invalid self-signature")
	}
}

// TestIssueUnknownTenantAndProfile rejects issuance for a missing tenant and a
// missing profile.
func TestIssueUnknownTenantAndProfile(t *testing.T) {
	env, ctx := initEnvWithTenant(t)

	if _, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "does-not-exist", CSR: testCSR(t, "x", pkix.ECDSAP256), Actor: advActor,
	}); err == nil {
		t.Fatal("issuance accepted for an unknown tenant")
	}

	if _, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "t1", Profile: "no-such-profile", CSR: testCSR(t, "x", pkix.ECDSAP256), Actor: advActor,
	}); err == nil {
		t.Fatal("issuance accepted for an unknown profile")
	}
}

// TestValidityClamping ensures an over-long validity request is clamped to the
// profile's MaxValidity (90 days for the default profile).
func TestValidityClamping(t *testing.T) {
	env, ctx := initEnvWithTenant(t)
	csr := testCSR(t, "long-lived", pkix.ECDSAP256)

	issued, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "t1", CSR: csr, Validity: 10000 * time.Hour, Actor: advActor,
	})
	if err != nil {
		t.Fatal(err)
	}
	notAfter := issued[0].Cert.X509.NotAfter
	cap90 := time.Now().Add(90 * 24 * time.Hour)
	if notAfter.After(cap90.Add(1 * time.Hour)) {
		t.Fatalf("NotAfter %s exceeds the 90-day cap %s", notAfter, cap90)
	}
	// And it should be near the cap, not the (much shorter) default.
	if notAfter.Before(time.Now().Add(89 * 24 * time.Hour)) {
		t.Fatalf("NotAfter %s is well under the 90-day cap; clamping looks wrong", notAfter)
	}
}

// TestProfileAllowedKeyAlgs enforces a profile that only permits ml-dsa-65.
func TestProfileAllowedKeyAlgs(t *testing.T) {
	env, ctx := initEnvWithTenant(t)

	// Restrict the default profile to ml-dsa-65 only, writing the tenant back
	// through the store (no public profile-update API in v0).
	tn, err := env.Manager.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	p := tn.Profiles["default"]
	p.AllowedKeyAlgs = []pkix.Algorithm{pkix.MLDSA65}
	tn.Profiles["default"] = p
	if err := store.PutJSON(ctx, env.Store, tenantsBucket, "t1", tn); err != nil {
		t.Fatal(err)
	}

	// ECDSA key is now disallowed.
	if _, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "t1", CSR: testCSR(t, "ecdsa-client", pkix.ECDSAP256), Actor: advActor,
	}); err == nil {
		t.Fatal("issuance accepted a disallowed ECDSA key")
	}

	// ml-dsa-65 key is allowed.
	if _, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "t1", CSR: testCSR(t, "mldsa-client", pkix.MLDSA65), Actor: advActor,
	}); err != nil {
		t.Fatalf("issuance rejected an allowed ml-dsa-65 key: %v", err)
	}
}

// TestRevokeTwiceAndUnknown rejects double revocation and revocation of an
// unknown serial.
func TestRevokeTwiceAndUnknown(t *testing.T) {
	env, ctx := initEnvWithTenant(t)
	issued, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "t1", CSR: testCSR(t, "revoke-me", pkix.ECDSAP256), Actor: advActor,
	})
	if err != nil {
		t.Fatal(err)
	}
	serial := issued[0].Cert.X509.SerialNumber.String()

	if err := env.Manager.Revoke(ctx, "t1", serial, 1, advActor); err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}
	if err := env.Manager.Revoke(ctx, "t1", serial, 1, advActor); err == nil {
		t.Fatal("second revoke of the same serial accepted")
	}
	if err := env.Manager.Revoke(ctx, "t1", "999999999999", 1, advActor); err == nil {
		t.Fatal("revoke of an unknown serial accepted")
	}
}

// TestTenantIDValidation rejects malformed tenant identifiers.
func TestTenantIDValidation(t *testing.T) {
	env, ctx := initEnvWithTenant(t)
	bad := []string{
		"UPPER",
		"a b",
		"",
		"../x",
		"this-id-is-way-too-long-0123456789012345678901234567890123456789012345", // 70 chars
	}
	for _, id := range bad {
		if _, err := env.Manager.CreateTenant(ctx, id, "", "", false, advActor); err == nil {
			t.Fatalf("CreateTenant accepted invalid id %q", id)
		}
	}
}

// TestCreateTenantDuplicate rejects re-creating an existing tenant.
func TestCreateTenantDuplicate(t *testing.T) {
	env, ctx := initEnvWithTenant(t)
	if _, err := env.Manager.CreateTenant(ctx, "dup", "", "", false, advActor); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.CreateTenant(ctx, "dup", "", "", false, advActor); err == nil {
		t.Fatal("duplicate tenant id accepted")
	}
}

// TestHybridTenantOnNonHybridRoot rejects a hybrid tenant when the root has no
// paired chain.
func TestHybridTenantOnNonHybridRoot(t *testing.T) {
	env, ctx := initEnvWithTenant(t) // root initialized without a PairAlg
	if _, err := env.Manager.CreateTenant(ctx, "hybrid-t", "", "", true, advActor); err == nil {
		t.Fatal("hybrid tenant accepted on a non-hybrid root")
	}
}
