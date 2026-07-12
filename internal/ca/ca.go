// Package ca implements the MnemoCA engine: root and per-tenant issuing CA
// lifecycle, profile-governed issuance, revocation, and CRLs. One instance
// serves many tenants (ADR-0006); hybrid strategy per ADR-0004.
package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	stdpkix "crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/signer"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// Chain selects which trust chain serves a request in hybrid deployments.
type Chain string

const (
	ChainPrimary Chain = "primary" // the root domain's main algorithm
	ChainPair    Chain = "pair"    // the paired (classical or PQ) chain
	ChainBoth    Chain = "both"    // dual issuance (ADR-0004 parallel hybrid)
)

// RootInfo describes the instance's root domain. A hybrid instance carries a
// paired second root (e.g. ML-DSA-87 primary + ECDSA P-384 pair).
type RootInfo struct {
	Name        string          `json:"name"`
	Alg         pkix.Algorithm  `json:"alg"`
	KeyRef      signer.KeyRef   `json:"key_ref"`
	CertPEM     []byte          `json:"cert_pem"`
	PairAlg     pkix.Algorithm  `json:"pair_alg,omitempty"`
	PairKeyRef  signer.KeyRef   `json:"pair_key_ref,omitempty"`
	PairCertPEM []byte          `json:"pair_cert_pem,omitempty"`
	AuditKeyRef signer.KeyRef   `json:"audit_key_ref"`
	AuditPubPEM []byte          `json:"audit_pub_pem"`
	CreatedAt   time.Time       `json:"created_at"`
}

// Tenant is one certificate tenant with its own issuing CA(s).
type Tenant struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	CreatedAt   time.Time          `json:"created_at"`
	Alg         pkix.Algorithm     `json:"alg"`
	KeyRef      signer.KeyRef      `json:"key_ref"`
	CertPEM     []byte             `json:"cert_pem"`
	PairAlg     pkix.Algorithm     `json:"pair_alg,omitempty"`
	PairKeyRef  signer.KeyRef      `json:"pair_key_ref,omitempty"`
	PairCertPEM []byte             `json:"pair_cert_pem,omitempty"`
	Profiles    map[string]Profile `json:"profiles"`
}

// Profile governs what a tenant may issue.
type Profile struct {
	Name            string        `json:"name"`
	DefaultValidity time.Duration `json:"default_validity"`
	MaxValidity     time.Duration `json:"max_validity"`
	// ServerAuth/ClientAuth are legacy EKU shorthands, honored only when
	// EKUs is empty.
	ServerAuth bool `json:"server_auth,omitempty"`
	ClientAuth bool `json:"client_auth,omitempty"`
	// EKUs is the explicit extended-key-usage grant (ProfileEKUNames).
	EKUs []string `json:"ekus,omitempty"`
	// KeyUsages is the key-usage grant (ProfileKeyUsageNames); empty means
	// digital_signature.
	KeyUsages      []string         `json:"key_usages,omitempty"`
	AllowedKeyAlgs []pkix.Algorithm `json:"allowed_key_algs,omitempty"` // empty = any registered
	Hybrid         Chain            `json:"hybrid,omitempty"`           // "" or ChainBoth for parallel dual issuance
}

// CertRecord is the stored record of an issued certificate.
type CertRecord struct {
	Serial     string         `json:"serial"`
	Tenant     string         `json:"tenant"`
	Profile    string         `json:"profile"`
	Chain      Chain          `json:"chain"`
	SubjectCN  string         `json:"subject_cn"`
	SANs       []string       `json:"sans,omitempty"`
	KeyAlg     pkix.Algorithm `json:"key_alg"`
	SigAlg     pkix.Algorithm `json:"sig_alg"`
	NotBefore  time.Time      `json:"not_before"`
	NotAfter   time.Time      `json:"not_after"`
	PEM        []byte         `json:"pem"`
	Revoked    bool           `json:"revoked"`
	RevokedAt  time.Time      `json:"revoked_at,omitempty"`
	ReasonCode int            `json:"reason_code,omitempty"`
}

// Issued is one issuance result: the leaf plus its chain up to the root.
type Issued struct {
	Chain Chain
	Cert  *pkix.Certificate
	Path  []*pkix.Certificate // leaf, issuing CA, root
}

// Manager is the CA engine.
type Manager struct {
	Store   store.Store
	Signers *signer.Registry
	Audit   audit.Logger
	Backend string // backend used for new keys ("softkey" in v0)
}

var (
	metaBucket    = []string{"meta"}
	tenantsBucket = []string{"tenants"}

	tenantIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

func certsBucket(tenant string) []string { return []string{"certs", tenant} }
func crlBucket(tenant string) []string   { return []string{"crl", tenant} }

// ErrExperimentalComposite is returned when a composite algorithm is used
// without the experimental opt-in (ADR-0004).
var ErrExperimentalComposite = errors.New("ca: composite algorithms are experimental; pass --experimental-composite")

// InitOptions configures InitRoot.
type InitOptions struct {
	Name                  string
	Alg                   pkix.Algorithm
	PairAlg               pkix.Algorithm // optional hybrid pair root
	RootValidity          time.Duration
	ExperimentalComposite bool
	Actor                 audit.Actor
}

// Root loads the root domain metadata.
func (m *Manager) Root(ctx context.Context) (*RootInfo, error) {
	var info RootInfo
	if err := store.GetJSON(ctx, m.Store, metaBucket, "root", &info); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("ca: not initialized (run `mnemoca init`)")
		}
		return nil, err
	}
	return &info, nil
}

func (m *Manager) checkExperimental(alg pkix.Algorithm, allowed bool) error {
	info, err := pkix.Lookup(alg)
	if err != nil {
		return err
	}
	if info.Experimental && !allowed {
		return ErrExperimentalComposite
	}
	return nil
}

func (m *Manager) newRootCert(name string, alg pkix.Algorithm, validity time.Duration, label string) (signer.KeyRef, *pkix.Certificate, error) {
	backend, err := m.Signers.Backend(m.Backend)
	if err != nil {
		return "", nil, err
	}
	key, ref, err := backend.Generate(context.Background(), alg, label)
	if err != nil {
		return "", nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return "", nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               stdpkix.Name{CommonName: name, Organization: []string{"MnemoCA"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	cert, err := pkix.CreateCertificate(tmpl, nil, key.Public(), key, alg)
	if err != nil {
		return "", nil, err
	}
	return ref, cert, nil
}

// InitRoot creates the root domain: root key+certificate (optionally a
// hybrid pair), and the audit key. Fails if already initialized.
func (m *Manager) InitRoot(ctx context.Context, opts InitOptions) (*RootInfo, error) {
	var existing RootInfo
	if err := store.GetJSON(ctx, m.Store, metaBucket, "root", &existing); err == nil {
		return nil, fmt.Errorf("ca: already initialized")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if err := m.checkExperimental(opts.Alg, opts.ExperimentalComposite); err != nil {
		return nil, err
	}
	if opts.RootValidity == 0 {
		opts.RootValidity = 20 * 365 * 24 * time.Hour
	}
	if opts.Name == "" {
		opts.Name = "MnemoCA Root"
	}

	ref, cert, err := m.newRootCert(opts.Name, opts.Alg, opts.RootValidity, "root/primary")
	if err != nil {
		return nil, fmt.Errorf("ca: creating root: %w", err)
	}
	info := RootInfo{
		Name:      opts.Name,
		Alg:       opts.Alg,
		KeyRef:    ref,
		CertPEM:   pkix.EncodeCertificatePEM(cert),
		CreatedAt: time.Now().UTC(),
	}
	if opts.PairAlg != "" {
		if err := m.checkExperimental(opts.PairAlg, opts.ExperimentalComposite); err != nil {
			return nil, err
		}
		pairRef, pairCert, err := m.newRootCert(opts.Name+" (pair)", opts.PairAlg, opts.RootValidity, "root/pair")
		if err != nil {
			return nil, fmt.Errorf("ca: creating pair root: %w", err)
		}
		info.PairAlg = opts.PairAlg
		info.PairKeyRef = pairRef
		info.PairCertPEM = pkix.EncodeCertificatePEM(pairCert)
	}

	// Dedicated audit key (ADR-0008).
	backend, err := m.Signers.Backend(m.Backend)
	if err != nil {
		return nil, err
	}
	auditKey, auditRef, err := backend.Generate(ctx, pkix.MLDSA65, "root/audit")
	if err != nil {
		return nil, fmt.Errorf("ca: creating audit key: %w", err)
	}
	auditPub, err := pkix.MarshalPublicKey(auditKey.Public())
	if err != nil {
		return nil, err
	}
	info.AuditKeyRef = auditRef
	info.AuditPubPEM = pemPublicKey(auditPub)

	if err := store.PutJSON(ctx, m.Store, metaBucket, "root", &info); err != nil {
		return nil, err
	}
	if err := m.Audit.Log(ctx, audit.Record{
		Actor:  opts.Actor,
		Action: "ca.init",
		Object: audit.Object{Type: "ca", ID: opts.Name},
		Detail: map[string]string{"alg": string(opts.Alg), "pair_alg": string(opts.PairAlg)},
	}); err != nil {
		return nil, err
	}
	return &info, nil
}

// DefaultProfiles returns the profile set new tenants start with.
func DefaultProfiles() map[string]Profile {
	return map[string]Profile{
		"default": {
			Name:            "default",
			DefaultValidity: 30 * 24 * time.Hour,
			MaxValidity:     90 * 24 * time.Hour,
			ServerAuth:      true,
			ClientAuth:      true,
		},
	}
}

// CreateTenant provisions a tenant with issuing CA(s) chained to the root.
// alg empty means "inherit the root's algorithm(s)".
func (m *Manager) CreateTenant(ctx context.Context, id, name string, alg pkix.Algorithm, hybrid bool, actor audit.Actor) (*Tenant, error) {
	if !tenantIDRe.MatchString(id) {
		return nil, fmt.Errorf("ca: invalid tenant id %q (lowercase alphanumeric and hyphens)", id)
	}
	var existing Tenant
	if err := store.GetJSON(ctx, m.Store, tenantsBucket, id, &existing); err == nil {
		return nil, fmt.Errorf("ca: tenant %q already exists", id)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	root, err := m.Root(ctx)
	if err != nil {
		return nil, err
	}
	if alg == "" {
		alg = root.Alg
	}
	if name == "" {
		name = id
	}

	issue := func(a pkix.Algorithm, rootRef signer.KeyRef, rootPEM []byte, label string) (signer.KeyRef, []byte, error) {
		rootCert, err := pkix.ParseCertificatePEM(rootPEM)
		if err != nil {
			return "", nil, err
		}
		rootSigner, err := m.Signers.Open(ctx, rootRef)
		if err != nil {
			return "", nil, err
		}
		backend, err := m.Signers.Backend(m.Backend)
		if err != nil {
			return "", nil, err
		}
		key, ref, err := backend.Generate(ctx, a, label)
		if err != nil {
			return "", nil, err
		}
		serial, err := newSerial()
		if err != nil {
			return "", nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               stdpkix.Name{CommonName: name + " Issuing CA", Organization: []string{"MnemoCA"}, OrganizationalUnit: []string{id}},
			NotBefore:             time.Now().Add(-5 * time.Minute),
			NotAfter:              rootCert.X509.NotAfter.Add(-24 * time.Hour),
			IsCA:                  true,
			MaxPathLenZero:        true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		cert, err := pkix.CreateCertificate(tmpl, rootCert, key.Public(), rootSigner, rootCert.Algorithm)
		if err != nil {
			return "", nil, err
		}
		return ref, pkix.EncodeCertificatePEM(cert), nil
	}

	t := Tenant{
		ID:        id,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		Alg:       alg,
		Profiles:  DefaultProfiles(),
	}
	t.KeyRef, t.CertPEM, err = issue(alg, root.KeyRef, root.CertPEM, "tenants/"+id+"/issuing")
	if err != nil {
		return nil, fmt.Errorf("ca: creating tenant issuing CA: %w", err)
	}
	if hybrid {
		if root.PairAlg == "" {
			return nil, fmt.Errorf("ca: hybrid tenant requires a hybrid root (init with --pair-alg)")
		}
		t.PairAlg = root.PairAlg
		t.PairKeyRef, t.PairCertPEM, err = issue(root.PairAlg, root.PairKeyRef, root.PairCertPEM, "tenants/"+id+"/issuing-pair")
		if err != nil {
			return nil, fmt.Errorf("ca: creating tenant pair issuing CA: %w", err)
		}
	}
	if err := store.PutJSON(ctx, m.Store, tenantsBucket, id, &t); err != nil {
		return nil, err
	}
	if err := m.Audit.Log(ctx, audit.Record{
		Tenant: id,
		Actor:  actor,
		Action: "tenant.create",
		Object: audit.Object{Type: "tenant", ID: id},
		Detail: map[string]string{"alg": string(alg), "hybrid": fmt.Sprint(hybrid)},
	}); err != nil {
		return nil, err
	}
	return &t, nil
}

// GetTenant loads a tenant by ID.
func (m *Manager) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	if err := store.GetJSON(ctx, m.Store, tenantsBucket, id, &t); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("ca: unknown tenant %q", id)
		}
		return nil, err
	}
	return &t, nil
}

// ListTenants returns all tenants.
func (m *Manager) ListTenants(ctx context.Context) ([]Tenant, error) {
	var out []Tenant
	err := store.ForEachJSON(ctx, m.Store, tenantsBucket, func(_ string, t Tenant) error {
		out = append(out, t)
		return nil
	})
	return out, err
}

func newSerial() (*big.Int, error) {
	// 127-bit random serial: positive, RFC 5280-compliant entropy.
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	return rand.Int(rand.Reader, limit)
}

func pemPublicKey(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
