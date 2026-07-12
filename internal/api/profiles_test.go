package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mnemoshare/mnemoca/pkg/mnemoca"
)

// createTenantKey mints a tenant-scoped API key via the operator key.
func createTenantKey(t *testing.T, srv *httptest.Server, operatorKey, tenant string) string {
	t.Helper()
	var created struct {
		Key string `json:"key"`
	}
	resp := call(t, srv, "POST", "/api/v1/apikeys", operatorKey,
		map[string]any{"role": "tenant", "tenant": tenant}, &created)
	wantStatus(t, resp, http.StatusCreated)
	return created.Key
}

// TestProfilesAPI drives the profile endpoints through the public client
// library, doubling as pkg/mnemoca's integration test.
func TestProfilesAPI(t *testing.T) {
	ctx := context.Background()
	srv, key := newTestServer(t)
	client := mnemoca.New(srv.URL, key)

	if _, err := client.CreateTenant(ctx, "prod", "Prod", "", false); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	// Default profile is present and surfaced in explicit EKU form.
	profiles, err := client.ListProfiles(ctx, "prod")
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "default" || len(profiles[0].EKUs) != 2 {
		t.Fatalf("initial profiles = %+v", profiles)
	}

	// Create an mTLS-client-only profile.
	if err := client.SetProfile(ctx, "prod", mnemoca.Profile{
		Name:            "mtls-client",
		DefaultValidity: "720h",
		MaxValidity:     "2160h",
		EKUs:            []string{"client_auth"},
		AllowedKeyAlgs:  []string{"ml-dsa-65"},
	}); err != nil {
		t.Fatalf("SetProfile: %v", err)
	}
	profiles, err = client.ListProfiles(ctx, "prod")
	if err != nil || len(profiles) != 2 {
		t.Fatalf("profiles after set = %+v, %v", profiles, err)
	}

	// Validation surfaces as a 4xx APIError.
	err = client.SetProfile(ctx, "prod", mnemoca.Profile{
		Name: "bad", DefaultValidity: "720h", MaxValidity: "2160h", EKUs: []string{"any"},
	})
	if apiErr, ok := err.(*mnemoca.APIError); !ok || apiErr.StatusCode != 400 {
		t.Fatalf("invalid EKU error = %v", err)
	}

	// Delete works; default is protected.
	if err := client.DeleteProfile(ctx, "prod", "mtls-client"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if err := client.DeleteProfile(ctx, "prod", "default"); err == nil {
		t.Fatal("default profile deletion allowed via API")
	}
}

// TestProfilesTenantScoping verifies a tenant-scoped key cannot manage
// another tenant's profiles.
func TestProfilesTenantScoping(t *testing.T) {
	ctx := context.Background()
	srv, operatorKey := newTestServer(t)
	operator := mnemoca.New(srv.URL, operatorKey)

	for _, id := range []string{"t1", "t2"} {
		if _, err := operator.CreateTenant(ctx, id, "", "", false); err != nil {
			t.Fatal(err)
		}
	}
	t1Key := createTenantKey(t, srv, operatorKey, "t1")
	scoped := mnemoca.New(srv.URL, t1Key)

	if err := scoped.SetProfile(ctx, "t1", mnemoca.Profile{
		Name: "own", DefaultValidity: "24h", MaxValidity: "48h", EKUs: []string{"client_auth"},
	}); err != nil {
		t.Fatalf("scoped key on own tenant: %v", err)
	}
	err := scoped.SetProfile(ctx, "t2", mnemoca.Profile{
		Name: "sneaky", DefaultValidity: "24h", MaxValidity: "48h", EKUs: []string{"client_auth"},
	})
	if apiErr, ok := err.(*mnemoca.APIError); !ok || apiErr.StatusCode != 403 {
		t.Fatalf("cross-tenant profile set = %v, want 403", err)
	}
	if _, err := scoped.ListProfiles(ctx, "t2"); err == nil {
		t.Fatal("cross-tenant profile list allowed")
	}
}
