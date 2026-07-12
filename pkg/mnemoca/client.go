// Package mnemoca is the public Go client for the MnemoCA REST API.
// It is dependency-free (stdlib only) so integrators can vendor it cheaply.
package mnemoca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to a MnemoCA server.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the underlying HTTP client.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithRootPEM pins the CA server's TLS trust anchor(s).
func WithRootPEM(pem []byte) Option {
	return func(c *Client) {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		c.http = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		}
	}
}

// New creates a client for baseURL (e.g. "https://ca.example.com")
// authenticating with apiKey ("mnemoca_<id>_<secret>").
func New(baseURL, apiKey string, opts ...Option) *Client {
	c := &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// APIError is a non-2xx response from the server.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mnemoca: %d: %s", e.StatusCode, e.Message)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = string(data)
		}
		return &APIError{StatusCode: resp.StatusCode, Message: e.Error}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// raw GETs a non-JSON resource (PEM bundle, DER CRL).
func (c *Client) raw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(data)}
	}
	return data, nil
}

// Tenant is a certificate tenant.
type Tenant struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Alg     string `json:"alg"`
	PairAlg string `json:"pair_alg,omitempty"`
	CertPEM string `json:"cert_pem,omitempty"`
}

// IssuedCertificate is one issuance result.
type IssuedCertificate struct {
	Chain    string    `json:"chain"`
	CertPEM  string    `json:"cert_pem"`
	ChainPEM string    `json:"chain_pem"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
}

// CertificateRecord is a stored certificate record (list responses).
type CertificateRecord struct {
	Serial    string    `json:"serial"`
	SubjectCN string    `json:"subject_cn"`
	SANs      []string  `json:"sans,omitempty"`
	KeyAlg    string    `json:"key_alg"`
	SigAlg    string    `json:"sig_alg"`
	Chain     string    `json:"chain"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   bool      `json:"revoked"`
}

// IssueRequest asks a tenant's issuing CA to sign a CSR.
type IssueRequest struct {
	CSRPEM                string `json:"csr_pem"`
	Profile               string `json:"profile,omitempty"`
	Validity              string `json:"validity,omitempty"` // Go duration, e.g. "720h"
	Chain                 string `json:"chain,omitempty"`    // primary|pair|both
	ExperimentalComposite bool   `json:"experimental_composite,omitempty"`
}

// Healthz reports server liveness.
func (c *Client) Healthz(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", nil, nil)
}

// Roots returns the root certificate PEM bundle.
func (c *Client) Roots(ctx context.Context) ([]byte, error) {
	return c.raw(ctx, "/roots")
}

// CRL returns the tenant's CRL in DER form ("primary" chain; use CRLPair for
// the paired chain).
func (c *Client) CRL(ctx context.Context, tenant string) ([]byte, error) {
	return c.raw(ctx, "/crl/"+tenant)
}

// CRLPair returns the tenant's paired-chain CRL in DER form.
func (c *Client) CRLPair(ctx context.Context, tenant string) ([]byte, error) {
	return c.raw(ctx, "/crl/"+tenant+"/pair")
}

// CreateTenant provisions a tenant with its own issuing CA.
func (c *Client) CreateTenant(ctx context.Context, id, name, alg string, hybrid bool) (*Tenant, error) {
	var out Tenant
	err := c.do(ctx, http.MethodPost, "/api/v1/tenants", map[string]any{
		"id": id, "name": name, "alg": alg, "hybrid": hybrid,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTenants lists all tenants (operator keys only).
func (c *Client) ListTenants(ctx context.Context) ([]Tenant, error) {
	var out []Tenant
	if err := c.do(ctx, http.MethodGet, "/api/v1/tenants", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Issue signs a CSR under the tenant's profile rules.
func (c *Client) Issue(ctx context.Context, tenant string, req IssueRequest) ([]IssuedCertificate, error) {
	var out struct {
		Certificates []IssuedCertificate `json:"certificates"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/tenants/"+tenant+"/issue", req, &out); err != nil {
		return nil, err
	}
	return out.Certificates, nil
}

// Revoke revokes a certificate by serial (RFC 5280 reason code).
func (c *Client) Revoke(ctx context.Context, tenant, serial string, reasonCode int) error {
	return c.do(ctx, http.MethodPost, "/api/v1/tenants/"+tenant+"/revoke", map[string]any{
		"serial": serial, "reason_code": reasonCode,
	}, nil)
}

// ListCertificates lists the tenant's issued certificate records.
func (c *Client) ListCertificates(ctx context.Context, tenant string) ([]CertificateRecord, error) {
	var out []CertificateRecord
	if err := c.do(ctx, http.MethodGet, "/api/v1/tenants/"+tenant+"/certificates", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
