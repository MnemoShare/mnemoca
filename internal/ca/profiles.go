package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/mnemoshare/mnemoca/internal/audit"
	"github.com/mnemoshare/mnemoca/internal/pkix"
	"github.com/mnemoshare/mnemoca/internal/store"
)

// Named extended key usages a profile may grant. Deliberately excludes
// ExtKeyUsageAny: a profile must say what it is for.
var profileEKUs = map[string]x509.ExtKeyUsage{
	"server_auth":      x509.ExtKeyUsageServerAuth,
	"client_auth":      x509.ExtKeyUsageClientAuth,
	"code_signing":     x509.ExtKeyUsageCodeSigning,
	"email_protection": x509.ExtKeyUsageEmailProtection,
	"time_stamping":    x509.ExtKeyUsageTimeStamping,
	"ocsp_signing":     x509.ExtKeyUsageOCSPSigning,
}

// Named key usages a profile may grant. Deliberately excludes cert_sign and
// crl_sign: leaf profiles must never mint CAs (issuing CA certs are created
// only by CreateTenant/InitRoot).
var profileKeyUsages = map[string]x509.KeyUsage{
	"digital_signature":  x509.KeyUsageDigitalSignature,
	"content_commitment": x509.KeyUsageContentCommitment,
	"key_encipherment":   x509.KeyUsageKeyEncipherment,
	"data_encipherment":  x509.KeyUsageDataEncipherment,
	"key_agreement":      x509.KeyUsageKeyAgreement,
}

// ProfileEKUNames and ProfileKeyUsageNames list the accepted names (sorted),
// for validation errors and API discovery.
func ProfileEKUNames() []string      { return sortedKeys(profileEKUs) }
func ProfileKeyUsageNames() []string { return sortedKeys(profileKeyUsages) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// extKeyUsages resolves the profile's EKU grant. The explicit EKUs list wins;
// the legacy ServerAuth/ClientAuth shorthands apply when it is empty.
func (p Profile) extKeyUsages() ([]x509.ExtKeyUsage, error) {
	if len(p.EKUs) == 0 {
		var out []x509.ExtKeyUsage
		if p.ServerAuth {
			out = append(out, x509.ExtKeyUsageServerAuth)
		}
		if p.ClientAuth {
			out = append(out, x509.ExtKeyUsageClientAuth)
		}
		return out, nil
	}
	out := make([]x509.ExtKeyUsage, 0, len(p.EKUs))
	for _, name := range p.EKUs {
		eku, ok := profileEKUs[name]
		if !ok {
			return nil, fmt.Errorf("ca: unknown eku %q (want one of %s)", name, strings.Join(ProfileEKUNames(), ", "))
		}
		out = append(out, eku)
	}
	return out, nil
}

// keyUsage resolves the profile's key usage bits; digital_signature when the
// list is empty (the pre-profile-API behavior).
func (p Profile) keyUsage() (x509.KeyUsage, error) {
	if len(p.KeyUsages) == 0 {
		return x509.KeyUsageDigitalSignature, nil
	}
	var out x509.KeyUsage
	for _, name := range p.KeyUsages {
		ku, ok := profileKeyUsages[name]
		if !ok {
			return 0, fmt.Errorf("ca: unknown key usage %q (want one of %s)", name, strings.Join(ProfileKeyUsageNames(), ", "))
		}
		out |= ku
	}
	return out, nil
}

// Validate checks a profile definition for storage.
func (p Profile) Validate() error {
	if !tenantIDRe.MatchString(p.Name) {
		return fmt.Errorf("ca: invalid profile name %q (lowercase alphanumeric and hyphens)", p.Name)
	}
	if p.DefaultValidity <= 0 || p.MaxValidity <= 0 {
		return fmt.Errorf("ca: profile validities must be positive")
	}
	if p.DefaultValidity > p.MaxValidity {
		return fmt.Errorf("ca: default validity %s exceeds max validity %s", p.DefaultValidity, p.MaxValidity)
	}
	if _, err := p.extKeyUsages(); err != nil {
		return err
	}
	if _, err := p.keyUsage(); err != nil {
		return err
	}
	for _, alg := range p.AllowedKeyAlgs {
		if _, err := pkix.Lookup(alg); err != nil {
			return err
		}
	}
	switch p.Hybrid {
	case "", ChainPrimary, ChainPair, ChainBoth:
	default:
		return fmt.Errorf("ca: invalid profile hybrid chain %q", p.Hybrid)
	}
	return nil
}

// SetProfile creates or replaces a named issuance profile on a tenant. The
// tenant document is updated atomically (safe across HA replicas).
func (m *Manager) SetProfile(ctx context.Context, tenant string, p Profile, actor audit.Actor) error {
	if err := p.Validate(); err != nil {
		return err
	}
	err := store.UpdateJSON(ctx, m.Store, tenantsBucket, tenant, false, func(t *Tenant) error {
		if t.Profiles == nil {
			t.Profiles = make(map[string]Profile)
		}
		t.Profiles[p.Name] = p
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("ca: unknown tenant %q", tenant)
	}
	if err != nil {
		return err
	}
	return m.Audit.Log(ctx, audit.Record{
		Tenant: tenant,
		Actor:  actor,
		Action: "profile.set",
		Object: audit.Object{Type: "profile", ID: p.Name},
		Detail: map[string]string{
			"ekus":       strings.Join(p.EKUs, ","),
			"key_usages": strings.Join(p.KeyUsages, ","),
			"default_validity": p.DefaultValidity.String(),
			"max_validity":     p.MaxValidity.String(),
		},
	})
}

// DeleteProfile removes a named profile. The "default" profile cannot be
// deleted (issuance falls back to it), only replaced via SetProfile.
func (m *Manager) DeleteProfile(ctx context.Context, tenant, name string, actor audit.Actor) error {
	if name == "default" {
		return fmt.Errorf("ca: the default profile cannot be deleted (replace it with SetProfile instead)")
	}
	err := store.UpdateJSON(ctx, m.Store, tenantsBucket, tenant, false, func(t *Tenant) error {
		if _, ok := t.Profiles[name]; !ok {
			return fmt.Errorf("ca: tenant %q has no profile %q", tenant, name)
		}
		delete(t.Profiles, name)
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("ca: unknown tenant %q", tenant)
	}
	if err != nil {
		return err
	}
	return m.Audit.Log(ctx, audit.Record{
		Tenant: tenant,
		Actor:  actor,
		Action: "profile.delete",
		Object: audit.Object{Type: "profile", ID: name},
	})
}
