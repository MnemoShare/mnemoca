package ca

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
)

type auditSpy struct {
	mu       sync.Mutex
	failOn   string // fail the first record with this action
	failed   bool
	afterLog func(action string)
	records  []audit.Record
}

func (a *auditSpy) Log(_ context.Context, rec audit.Record) error {
	a.mu.Lock()
	if a.failOn != "" && !a.failed && rec.Action == a.failOn {
		a.failed = true
		a.mu.Unlock()
		return errors.New("audit unavailable")
	}
	a.records = append(a.records, rec)
	hook := a.afterLog
	a.mu.Unlock()
	if hook != nil {
		hook(rec.Action)
	}
	return nil
}

func (a *auditSpy) find(action string) *audit.Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.records {
		if a.records[i].Action == action {
			return &a.records[i]
		}
	}
	return nil
}

// ctxStore refuses writes under a cancelled context, like a networked store.
type ctxStore struct{ store.Store }

func (c ctxStore) Put(ctx context.Context, p []string, k string, d []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Store.Put(ctx, p, k, d)
}

func (c ctxStore) Update(ctx context.Context, p []string, k string, create bool, fn func([]byte) ([]byte, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Store.Update(ctx, p, k, create, fn)
}

func hybridEnv(t *testing.T) (*Env, audit.Actor) {
	t.Helper()
	ctx := context.Background()
	env := testEnv(t)
	actor := audit.Actor{Type: "operator", ID: "test"}
	if _, err := env.Init(ctx, InitOptions{Alg: pkix.MLDSA87, PairAlg: pkix.ECDSAP384, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Manager.CreateTenant(ctx, "acme-corp", "ACME", pkix.MLDSA65, true, actor); err != nil {
		t.Fatal(err)
	}
	return env, actor
}

// The request context is cancelled mid-issuance; the compensating revoke must
// still land, and the abandonment must be audited.
func TestAbandonedIssuanceRevokesUnderCancelledContext(t *testing.T) {
	env, actor := hybridEnv(t)
	spy := &auditSpy{}
	env.Manager.Audit = spy
	env.Manager.Store = ctxStore{env.Manager.Store}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel right after the primary's issuance is durable: the pair step and
	// any ctx-bound compensation then fail.
	spy.afterLog = func(action string) {
		if action == "cert.issue" {
			cancel()
		}
	}
	_, err := env.Manager.Issue(ctx, IssueRequest{
		Tenant: "acme-corp", CSR: testCSR(t, "mtls-client", pkix.ECDSAP256), Chain: ChainBoth, Actor: actor,
	})
	if err == nil {
		t.Fatal("Issue succeeded under cancellation")
	}
	recs, lerr := env.Manager.ListCertificates(context.Background(), "acme-corp")
	if lerr != nil || len(recs) != 1 {
		t.Fatalf("records = %d, err = %v", len(recs), lerr)
	}
	if !recs[0].Revoked {
		t.Fatalf("serial %s left valid after cancellation", recs[0].Serial)
	}
	ab := spy.find("cert.issue.abandoned")
	if ab == nil {
		t.Fatal("no cert.issue.abandoned audit record")
	}
	if !strings.Contains(ab.Detail["revoked"], recs[0].Serial) || ab.Detail["left_issued"] != "" {
		t.Fatalf("abandoned detail = %v", ab.Detail)
	}
}

// issueOne persists the certificate before the write-ahead audit; if the audit
// write fails the certificate is withheld, so it must also be revoked.
func TestAuditFailureRevokesWithheldCertificate(t *testing.T) {
	env, actor := hybridEnv(t)
	spy := &auditSpy{failOn: "cert.issue"}
	env.Manager.Audit = spy

	_, err := env.Manager.Issue(context.Background(), IssueRequest{
		Tenant: "acme-corp", CSR: testCSR(t, "mtls-client", pkix.ECDSAP256), Chain: ChainPrimary, Actor: actor,
	})
	if err == nil {
		t.Fatal("Issue succeeded although the audit write failed")
	}
	recs, _ := env.Manager.ListCertificates(context.Background(), "acme-corp")
	if len(recs) != 1 || !recs[0].Revoked || recs[0].ReasonCode != 5 {
		t.Fatalf("withheld certificate not revoked: %+v", recs)
	}
	if !strings.Contains(err.Error(), recs[0].Serial) {
		t.Fatalf("error %q does not name serial %s", err, recs[0].Serial)
	}
	if spy.find("cert.issue.abandoned") == nil {
		t.Fatal("abandonment not audited")
	}
}
