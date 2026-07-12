package ca

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/signer"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// Env is an opened MnemoCA data directory: store, signer backends, audit
// log, and the Manager over them. Layout:
//
//	<dir>/ca.db      bbolt store
//	<dir>/keys/      softkey backend
//	<dir>/audit.log  hash-chained audit log
type Env struct {
	Dir     string
	Store   *store.Store
	Signers *signer.Registry
	Manager *Manager
	AuditLog *audit.Log // nil until the root (and audit key) exists
}

// OpenEnv opens the data directory. The audit log is only opened when the CA
// is initialized (the audit key exists); before InitRoot, Manager.Audit is a
// buffered bootstrap that flushes into the real log via FinishInit.
func OpenEnv(dir string, passphrase []byte) (*Env, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(filepath.Join(dir, "ca.db"))
	if err != nil {
		return nil, err
	}
	soft, err := signer.NewSoftkey(filepath.Join(dir, "keys"), passphrase)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	reg := signer.NewRegistry(soft, signer.PKCS11{}, signer.KMS{})
	env := &Env{
		Dir:     dir,
		Store:   st,
		Signers: reg,
	}
	env.Manager = &Manager{Store: st, Signers: reg, Audit: audit.Nop{}, Backend: "softkey"}

	// If already initialized, open the audit log with the audit key.
	var info RootInfo
	if err := st.GetJSON(metaBucket, "root", &info); err == nil {
		if err := env.openAudit(&info); err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	return env, nil
}

func (e *Env) openAudit(info *RootInfo) error {
	auditSigner, err := e.Signers.Open(context.Background(), info.AuditKeyRef)
	if err != nil {
		return fmt.Errorf("ca: opening audit key: %w", err)
	}
	log, err := audit.Open(filepath.Join(e.Dir, "audit.log"), auditSigner, "audit-1")
	if err != nil {
		return err
	}
	e.AuditLog = log
	e.Manager.Audit = log
	return nil
}

// Init initializes the root domain and switches the manager onto the real
// audit log (the ca.init record is the first entry after genesis).
func (e *Env) Init(ctx context.Context, opts InitOptions) (*RootInfo, error) {
	if e.AuditLog != nil {
		return nil, fmt.Errorf("ca: already initialized")
	}
	// InitRoot generates the audit key; run it with a Nop logger, then open
	// the real log and write the ca.init record there.
	info, err := e.Manager.InitRoot(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := e.openAudit(info); err != nil {
		return nil, err
	}
	if err := e.Manager.Audit.Log(ctx, audit.Record{
		Actor:  opts.Actor,
		Action: "ca.init",
		Object: audit.Object{Type: "ca", ID: info.Name},
		Detail: map[string]string{"alg": string(info.Alg), "pair_alg": string(info.PairAlg)},
	}); err != nil {
		return nil, err
	}
	return info, nil
}

// Close releases the store and audit log.
func (e *Env) Close() error {
	if e.AuditLog != nil {
		_ = e.AuditLog.Close()
	}
	return e.Store.Close()
}
