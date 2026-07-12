package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// IssueRequest asks for certificate issuance from a tenant's issuing CA.
type IssueRequest struct {
	Tenant  string
	Profile string
	CSR     *pkix.CertificateRequest
	// Validity clamps to the profile's MaxValidity; zero means the profile
	// default.
	Validity time.Duration
	// Chain selects primary/pair/both for hybrid tenants (ADR-0004);
	// empty means primary, or the profile's Hybrid setting if configured.
	Chain Chain
	// ExperimentalComposite must be set to issue with/for composite
	// algorithms.
	ExperimentalComposite bool
	Actor                 audit.Actor
}

// Issue validates the CSR against the tenant profile and issues from the
// selected chain(s). The certificate is not returned until its audit record
// is durable (write-ahead auditing, ADR-0008).
func (m *Manager) Issue(ctx context.Context, req IssueRequest) ([]Issued, error) {
	t, err := m.GetTenant(req.Tenant)
	if err != nil {
		return nil, err
	}
	if req.Profile == "" {
		req.Profile = "default"
	}
	profile, ok := t.Profiles[req.Profile]
	if !ok {
		return nil, fmt.Errorf("ca: tenant %q has no profile %q", t.ID, req.Profile)
	}
	if req.CSR == nil {
		return nil, fmt.Errorf("ca: missing CSR")
	}
	if err := req.CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: CSR signature invalid: %w", err)
	}
	keyInfo, err := pkix.Lookup(req.CSR.PublicKeyAlgorithm)
	if err != nil {
		return nil, err
	}
	if keyInfo.Experimental && !req.ExperimentalComposite {
		return nil, ErrExperimentalComposite
	}
	if len(profile.AllowedKeyAlgs) > 0 && !slices.Contains(profile.AllowedKeyAlgs, req.CSR.PublicKeyAlgorithm) {
		return nil, fmt.Errorf("ca: profile %q does not allow key algorithm %q", profile.Name, req.CSR.PublicKeyAlgorithm)
	}

	validity := req.Validity
	if validity == 0 {
		validity = profile.DefaultValidity
	}
	if validity > profile.MaxValidity {
		validity = profile.MaxValidity
	}

	chain := req.Chain
	if chain == "" {
		chain = profile.Hybrid
	}
	if chain == "" {
		chain = ChainPrimary
	}
	if (chain == ChainPair || chain == ChainBoth) && t.PairAlg == "" {
		return nil, fmt.Errorf("ca: tenant %q has no pair chain", t.ID)
	}

	var targets []Chain
	switch chain {
	case ChainPrimary:
		targets = []Chain{ChainPrimary}
	case ChainPair:
		targets = []Chain{ChainPair}
	case ChainBoth:
		targets = []Chain{ChainPrimary, ChainPair}
	default:
		return nil, fmt.Errorf("ca: invalid chain %q", chain)
	}

	root, err := m.Root()
	if err != nil {
		return nil, err
	}

	var out []Issued
	for _, target := range targets {
		issued, err := m.issueOne(ctx, t, root, profile, req, target, validity)
		if err != nil {
			return nil, err
		}
		out = append(out, *issued)
	}
	return out, nil
}

func (m *Manager) issueOne(ctx context.Context, t *Tenant, root *RootInfo, profile Profile, req IssueRequest, target Chain, validity time.Duration) (*Issued, error) {
	keyRef, certPEM, rootPEM := t.KeyRef, t.CertPEM, root.CertPEM
	if target == ChainPair {
		keyRef, certPEM, rootPEM = t.PairKeyRef, t.PairCertPEM, root.PairCertPEM
	}
	issuingCert, err := pkix.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	rootCert, err := pkix.ParseCertificatePEM(rootPEM)
	if err != nil {
		return nil, err
	}
	issuingSigner, err := m.Signers.Open(ctx, keyRef)
	if err != nil {
		return nil, err
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	var eku []x509.ExtKeyUsage
	if profile.ServerAuth {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if profile.ClientAuth {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		RawSubject:     req.CSR.RawSubject,
		NotBefore:      time.Now().Add(-5 * time.Minute),
		NotAfter:       time.Now().Add(validity),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    eku,
		DNSNames:       req.CSR.DNSNames,
		EmailAddresses: req.CSR.EmailAddresses,
		IPAddresses:    req.CSR.IPAddresses,
		URIs:           req.CSR.URIs,
	}
	cert, err := pkix.CreateCertificate(tmpl, issuingCert, req.CSR.PublicKey, issuingSigner, issuingCert.PublicKeyAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("ca: signing certificate: %w", err)
	}

	rec := CertRecord{
		Serial:    serial.String(),
		Tenant:    t.ID,
		Profile:   profile.Name,
		Chain:     target,
		SubjectCN: req.CSR.Subject.CommonName,
		SANs:      sanSummary(req.CSR),
		KeyAlg:    cert.PublicKeyAlgorithm,
		SigAlg:    cert.Algorithm,
		NotBefore: cert.X509.NotBefore,
		NotAfter:  cert.X509.NotAfter,
		PEM:       pkix.EncodeCertificatePEM(cert),
	}
	if err := m.Store.PutJSON(certsBucket(t.ID), rec.Serial, &rec); err != nil {
		return nil, err
	}
	// Write-ahead audit: the caller never sees a certificate whose issuance
	// is not durably recorded.
	if err := m.Audit.Log(ctx, audit.Record{
		Tenant: t.ID,
		Actor:  req.Actor,
		Action: "cert.issue",
		Object: audit.Object{Type: "cert", ID: rec.Serial},
		Detail: map[string]string{
			"cn": rec.SubjectCN, "sans": strings.Join(rec.SANs, ","),
			"profile": profile.Name, "chain": string(target),
			"key_alg": string(rec.KeyAlg), "sig_alg": string(rec.SigAlg),
			"not_after": rec.NotAfter.Format(time.RFC3339),
		},
	}); err != nil {
		return nil, fmt.Errorf("ca: audit append failed, withholding certificate: %w", err)
	}
	return &Issued{Chain: target, Cert: cert, Path: []*pkix.Certificate{cert, issuingCert, rootCert}}, nil
}

func sanSummary(csr *pkix.CertificateRequest) []string {
	var out []string
	out = append(out, csr.DNSNames...)
	out = append(out, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		out = append(out, ip.String())
	}
	for _, u := range csr.URIs {
		out = append(out, u.String())
	}
	return out
}

// Revoke marks a certificate revoked. reasonCode follows RFC 5280 §5.3.1.
func (m *Manager) Revoke(ctx context.Context, tenant, serial string, reasonCode int, actor audit.Actor) error {
	err := store.UpdateJSON(m.Store, certsBucket(tenant), serial, false, func(rec *CertRecord) error {
		if rec.Revoked {
			return fmt.Errorf("ca: certificate %s already revoked", serial)
		}
		rec.Revoked = true
		rec.RevokedAt = time.Now().UTC()
		rec.ReasonCode = reasonCode
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("ca: unknown certificate %s in tenant %s", serial, tenant)
	}
	if err != nil {
		return err
	}
	return m.Audit.Log(ctx, audit.Record{
		Tenant: tenant,
		Actor:  actor,
		Action: "cert.revoke",
		Object: audit.Object{Type: "cert", ID: serial},
		Detail: map[string]string{"reason_code": fmt.Sprint(reasonCode)},
	})
}

// ListCertificates returns all issued certificate records for a tenant.
func (m *Manager) ListCertificates(tenant string) ([]CertRecord, error) {
	if _, err := m.GetTenant(tenant); err != nil {
		return nil, err
	}
	var out []CertRecord
	err := store.ForEachJSON(m.Store, certsBucket(tenant), func(_ string, rec CertRecord) error {
		out = append(out, rec)
		return nil
	})
	return out, err
}

// GetCertificate loads one certificate record.
func (m *Manager) GetCertificate(tenant, serial string) (*CertRecord, error) {
	var rec CertRecord
	if err := m.Store.GetJSON(certsBucket(tenant), serial, &rec); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("ca: unknown certificate %s in tenant %s", serial, tenant)
		}
		return nil, err
	}
	return &rec, nil
}

// BuildCRL signs a fresh CRL for the tenant's chain covering all revoked
// certificates. nextUpdate defaults to 24h.
func (m *Manager) BuildCRL(ctx context.Context, tenant string, chain Chain, actor audit.Actor) (*pkix.CRL, error) {
	t, err := m.GetTenant(tenant)
	if err != nil {
		return nil, err
	}
	keyRef, certPEM := t.KeyRef, t.CertPEM
	if chain == ChainPair {
		if t.PairAlg == "" {
			return nil, fmt.Errorf("ca: tenant %q has no pair chain", t.ID)
		}
		keyRef, certPEM = t.PairKeyRef, t.PairCertPEM
	}
	issuingCert, err := pkix.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	issuingSigner, err := m.Signers.Open(ctx, keyRef)
	if err != nil {
		return nil, err
	}

	var revoked []pkix.RevokedEntry
	err = store.ForEachJSON(m.Store, certsBucket(tenant), func(_ string, rec CertRecord) error {
		if !rec.Revoked || rec.Chain != chainOrPrimary(chain) {
			return nil
		}
		serial, ok := new(big.Int).SetString(rec.Serial, 10)
		if !ok {
			return fmt.Errorf("ca: corrupt serial %q", rec.Serial)
		}
		revoked = append(revoked, pkix.RevokedEntry{
			SerialNumber:   serial,
			RevocationTime: rec.RevokedAt,
			ReasonCode:     rec.ReasonCode,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	num, err := m.Store.NextSeq(crlBucket(tenant))
	if err != nil {
		return nil, err
	}
	crl, err := pkix.CreateCRL(issuingCert, issuingSigner, issuingCert.PublicKeyAlgorithm,
		revoked, new(big.Int).SetUint64(num), time.Now(), time.Now().Add(24*time.Hour))
	if err != nil {
		return nil, err
	}
	if err := m.Audit.Log(ctx, audit.Record{
		Tenant: tenant,
		Actor:  actor,
		Action: "crl.publish",
		Object: audit.Object{Type: "crl", ID: fmt.Sprint(num)},
		Detail: map[string]string{"revoked_count": fmt.Sprint(len(revoked)), "chain": string(chainOrPrimary(chain))},
	}); err != nil {
		return nil, err
	}
	return crl, nil
}

func chainOrPrimary(c Chain) Chain {
	if c == "" {
		return ChainPrimary
	}
	return c
}
