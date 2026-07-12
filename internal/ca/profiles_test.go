package ca

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
)

func TestProfileLifecycle(t *testing.T) {
	ctx := context.Background()
	env := testEnv(t)
	actor := audit.Actor{Type: "operator", ID: "test"}
	if _, err := env.Init(ctx, InitOptions{Alg: pkix.MLDSA65, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.CreateTenant(ctx, "t1", "", "", false, actor); err != nil {
		t.Fatal(err)
	}

	// An mTLS-client-only profile restricted to ML-DSA-65 keys.
	mtls := Profile{
		Name:            "mtls-client",
		DefaultValidity: 24 * time.Hour,
		MaxValidity:     48 * time.Hour,
		EKUs:            []string{"client_auth"},
		KeyUsages:       []string{"digital_signature"},
		AllowedKeyAlgs:  []pkix.Algorithm{pkix.MLDSA65},
	}
	if err := env.Manager.SetProfile(ctx, "t1", mtls, actor); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}

	// Issuance under the profile: client-auth EKU only, no server-auth.
	csr := testCSR(t, "client-1", pkix.MLDSA65)
	issued, err := env.Manager.Issue(ctx, IssueRequest{Tenant: "t1", Profile: "mtls-client", CSR: csr, Actor: actor})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cert := issued[0].Cert.X509
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("EKUs = %v, want [client_auth]", cert.ExtKeyUsage)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("KeyUsage = %v", cert.KeyUsage)
	}

	// Key-algorithm restriction enforced.
	ecdsaCSR := testCSR(t, "client-2", pkix.ECDSAP256)
	if _, err := env.Manager.Issue(ctx, IssueRequest{Tenant: "t1", Profile: "mtls-client", CSR: ecdsaCSR, Actor: actor}); err == nil {
		t.Fatal("ECDSA CSR accepted by ML-DSA-only profile")
	}

	// A signing profile with content_commitment and email_protection.
	signing := Profile{
		Name:            "sp-signing",
		DefaultValidity: 24 * time.Hour,
		MaxValidity:     24 * time.Hour,
		EKUs:            []string{"email_protection"},
		KeyUsages:       []string{"digital_signature", "content_commitment"},
	}
	if err := env.Manager.SetProfile(ctx, "t1", signing, actor); err != nil {
		t.Fatal(err)
	}
	issued, err = env.Manager.Issue(ctx, IssueRequest{Tenant: "t1", Profile: "sp-signing", CSR: testCSR(t, "signer-1", pkix.MLDSA65), Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	cert = issued[0].Cert.X509
	if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment {
		t.Fatalf("KeyUsage = %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageEmailProtection {
		t.Fatalf("EKUs = %v, want [email_protection]", cert.ExtKeyUsage)
	}

	// Deletion: named profiles yes, default never; unknown profile errors.
	if err := env.Manager.DeleteProfile(ctx, "t1", "sp-signing", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.Issue(ctx, IssueRequest{Tenant: "t1", Profile: "sp-signing", CSR: csr, Actor: actor}); err == nil {
		t.Fatal("issued under a deleted profile")
	}
	if err := env.Manager.DeleteProfile(ctx, "t1", "default", actor); err == nil {
		t.Fatal("default profile deletion allowed")
	}
	if err := env.Manager.DeleteProfile(ctx, "t1", "nope", actor); err == nil {
		t.Fatal("deleting unknown profile succeeded")
	}
}

func TestProfileValidation(t *testing.T) {
	base := Profile{Name: "p", DefaultValidity: time.Hour, MaxValidity: 2 * time.Hour}
	cases := []struct {
		name   string
		mutate func(*Profile)
	}{
		{"bad name", func(p *Profile) { p.Name = "Bad Name!" }},
		{"zero validity", func(p *Profile) { p.DefaultValidity = 0 }},
		{"default exceeds max", func(p *Profile) { p.DefaultValidity = 3 * time.Hour }},
		{"unknown eku", func(p *Profile) { p.EKUs = []string{"any"} }},
		{"unknown key usage", func(p *Profile) { p.KeyUsages = []string{"cert_sign"} }},
		{"unknown key alg", func(p *Profile) { p.AllowedKeyAlgs = []pkix.Algorithm{"rsa-1024"} }},
		{"bad hybrid", func(p *Profile) { p.Hybrid = "quantum" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid profile rejected: %v", err)
	}
}

// TestProfileLegacyShorthand ensures pre-existing stored profiles (bool
// shorthands, no EKU list) keep issuing exactly as before.
func TestProfileLegacyShorthand(t *testing.T) {
	p := Profile{ServerAuth: true, ClientAuth: true}
	ekus, err := p.extKeyUsages()
	if err != nil || len(ekus) != 2 {
		t.Fatalf("legacy EKUs = %v, %v", ekus, err)
	}
	ku, err := p.keyUsage()
	if err != nil || ku != x509.KeyUsageDigitalSignature {
		t.Fatalf("legacy key usage = %v, %v", ku, err)
	}
}
