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

// Config selects and configures the storage backend (ADR-0010).
type Config struct {
	Dir        string // data directory (bolt file, softkey files, audit.log)
	Passphrase []byte // key-encryption passphrase (softkey / storekey)
	DB         string // "bolt" (default) or "mongo"
	MongoURI   string // mongo mode: connection URI
	MongoDB    string // mongo mode: database name (default "mnemoca")
}

// Env is an opened MnemoCA environment: store, signer backends, audit log,
// and the Manager over them.
//
// bolt mode (default) uses the data directory:
//
//	<dir>/ca.db      bbolt store
//	<dir>/keys/      softkey backend
//	<dir>/audit.log  hash-chained audit log
//
// mongo mode (HA) keeps documents, key envelopes ("storekey"), and the audit
// chain in MongoDB, so replicas are stateless (ADR-0010).
type Env struct {
	Dir      string
	DB       string // backend kind: "bolt" or "mongo"
	Store    store.Store
	Signers  *signer.Registry
	Manager  *Manager
	AuditLog audit.ChainLogger // nil until the root (and audit key) exists
}

// OpenEnv opens a bolt-backed data directory (back-compat wrapper).
func OpenEnv(dir string, passphrase []byte) (*Env, error) {
	return OpenEnvConfig(context.Background(), Config{Dir: dir, Passphrase: passphrase})
}

// OpenEnvConfig opens the environment described by cfg. The audit log is only
// opened when the CA is initialized (the audit key exists); before InitRoot,
// Manager.Audit is a no-op that Init replaces with the real log.
func OpenEnvConfig(ctx context.Context, cfg Config) (*Env, error) {
	if cfg.DB == "" {
		cfg.DB = "bolt"
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	soft, err := signer.NewSoftkey(filepath.Join(cfg.Dir, "keys"), cfg.Passphrase)
	if err != nil {
		return nil, err
	}

	var st store.Store
	var backend string
	// PKCS#11 HSM backend: configured entirely from the environment; the
	// unconfigured zero value stays registered so pkcs11: refs fail with a
	// clear error instead of an unknown-backend error (see docs/hsm.md).
	hsm := signer.Backend(signer.PKCS11{})
	if module := os.Getenv("MNEMOCA_PKCS11_MODULE"); module != "" {
		h, err := signer.NewPKCS11(signer.PKCS11Config{
			ModulePath: module,
			TokenLabel: os.Getenv("MNEMOCA_PKCS11_TOKEN"),
			PIN:        os.Getenv("MNEMOCA_PKCS11_PIN"),
		})
		if err != nil {
			return nil, fmt.Errorf("ca: configuring pkcs11 backend: %w", err)
		}
		hsm = h
	}
	backends := []signer.Backend{soft, hsm, signer.KMS{}}
	switch cfg.DB {
	case "bolt":
		st, err = store.Open(filepath.Join(cfg.Dir, "ca.db"))
		if err != nil {
			return nil, err
		}
		backend = "softkey"
	case "mongo":
		st, err = store.OpenMongo(ctx, cfg.MongoURI, cfg.MongoDB)
		if err != nil {
			return nil, err
		}
		sk, err := signer.NewStorekey(st, cfg.Passphrase)
		if err != nil {
			_ = st.Close()
			return nil, err
		}
		backends = append(backends, sk)
		backend = "storekey"
	default:
		return nil, fmt.Errorf("ca: unknown db backend %q (want bolt or mongo)", cfg.DB)
	}

	reg := signer.NewRegistry(backends...)
	env := &Env{
		Dir:     cfg.Dir,
		DB:      cfg.DB,
		Store:   st,
		Signers: reg,
	}
	env.Manager = &Manager{Store: st, Signers: reg, Audit: audit.Nop{}, Backend: backend}

	// If already initialized, open the audit log with the audit key.
	var info RootInfo
	if err := store.GetJSON(ctx, st, metaBucket, "root", &info); err == nil {
		if err := env.openAudit(ctx, &info); err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	return env, nil
}

func (e *Env) openAudit(ctx context.Context, info *RootInfo) error {
	auditSigner, err := e.Signers.Open(ctx, info.AuditKeyRef)
	if err != nil {
		return fmt.Errorf("ca: opening audit key: %w", err)
	}
	var log audit.ChainLogger
	if e.DB == "mongo" {
		log, err = audit.OpenStore(ctx, e.Store, auditSigner, "audit-1")
	} else {
		log, err = audit.Open(filepath.Join(e.Dir, "audit.log"), auditSigner, "audit-1")
	}
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
	if err := e.openAudit(ctx, info); err != nil {
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
