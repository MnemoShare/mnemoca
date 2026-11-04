package ca

import (
	"context"
	"strings"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// A chain=both request whose pair step fails must not leave the primary
// certificate valid, and the error must say which serial was affected.
func TestIssueBothPairFailureRevokesPrimary(t *testing.T) {
	ctx := context.Background()
	env := testEnv(t)
	actor := audit.Actor{Type: "operator", ID: "test"}
	if _, err := env.Init(ctx, InitOptions{Alg: pkix.MLDSA87, PairAlg: pkix.ECDSAP384, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.CreateTenant(ctx, "acme-corp", "ACME", pkix.MLDSA65, true, actor); err != nil {
		t.Fatal(err)
	}
	// Break only the pair issuing certificate so the second step fails.
	err := store.UpdateJSON(ctx, env.Store, tenantsBucket, "acme-corp", false, func(tn *Tenant) error {
		tn.PairCertPEM = []byte("not a certificate")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = env.Manager.Issue(ctx, IssueRequest{
		Tenant: "acme-corp", CSR: testCSR(t, "mtls-client", pkix.ECDSAP256), Chain: ChainBoth, Actor: actor,
	})
	if err == nil {
		t.Fatal("Issue succeeded with a broken pair chain")
	}

	recs, lerr := env.Manager.ListCertificates(ctx, "acme-corp")
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, r := range recs {
		if !r.Revoked {
			t.Fatalf("serial %s left valid after a failed chain=both issuance", r.Serial)
		}
		if r.ReasonCode != 5 {
			t.Fatalf("serial %s revoked with reason %d, want 5 (cessationOfOperation)", r.Serial, r.ReasonCode)
		}
		if !strings.Contains(err.Error(), r.Serial) {
			t.Fatalf("error %q does not name serial %s", err, r.Serial)
		}
	}
	if len(recs) == 0 {
		t.Fatal("expected the primary to have been issued then revoked")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("error %q does not say the primary was revoked", err)
	}
}
