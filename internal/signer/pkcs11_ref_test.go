package signer

// KeyRef scheme tests build with and without cgo: the ref format is shared
// by the real backend and the non-cgo stub.

import "testing"

func TestPKCS11RefRoundTrip(t *testing.T) {
	cases := []struct {
		name                 string
		module, token, label string
		want                 KeyRef
	}{
		{
			name:   "typical",
			module: "/opt/homebrew/lib/softhsm/libsofthsm2.so",
			token:  "mnemoca-test",
			label:  "root-2026",
			want:   "pkcs11:module=/opt/homebrew/lib/softhsm/libsofthsm2.so;token=mnemoca-test;label=root-2026",
		},
		{
			name:   "equals sign in values",
			module: "/usr/lib/x=y/libsofthsm2.so",
			token:  "tok=1",
			label:  "issuing=a",
			want:   "pkcs11:module=/usr/lib/x=y/libsofthsm2.so;token=tok=1;label=issuing=a",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := formatPKCS11Ref(tc.module, tc.token, tc.label)
			if err != nil {
				t.Fatalf("formatPKCS11Ref: %v", err)
			}
			if ref != tc.want {
				t.Fatalf("formatPKCS11Ref = %q, want %q", ref, tc.want)
			}
			if got := ref.Scheme(); got != "pkcs11" {
				t.Fatalf("Scheme() = %q, want pkcs11", got)
			}
			module, token, label, err := parsePKCS11Ref(ref)
			if err != nil {
				t.Fatalf("parsePKCS11Ref(%q): %v", ref, err)
			}
			if module != tc.module || token != tc.token || label != tc.label {
				t.Fatalf("round trip = (%q, %q, %q), want (%q, %q, %q)",
					module, token, label, tc.module, tc.token, tc.label)
			}
		})
	}
}

func TestPKCS11RefFormatRejectsInvalidComponents(t *testing.T) {
	cases := []struct {
		name                 string
		module, token, label string
	}{
		{"empty module", "", "tok", "lbl"},
		{"empty token", "/lib.so", "", "lbl"},
		{"empty label", "/lib.so", "tok", ""},
		{"semicolon in label", "/lib.so", "tok", "a;b"},
		{"semicolon in token", "/lib.so", "t;ok", "lbl"},
		{"semicolon in module", "/li;b.so", "tok", "lbl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := formatPKCS11Ref(tc.module, tc.token, tc.label); err == nil {
				t.Fatalf("formatPKCS11Ref(%q, %q, %q) succeeded, want error",
					tc.module, tc.token, tc.label)
			}
		})
	}
}

func TestPKCS11RefParseRejectsMalformedRefs(t *testing.T) {
	cases := []struct {
		name string
		ref  KeyRef
	}{
		{"wrong scheme", "softkey:tenants/acme/issuing.key"},
		{"no scheme", "module=/lib.so;token=t;label=l"},
		{"missing label", "pkcs11:module=/lib.so;token=t"},
		{"missing module", "pkcs11:token=t;label=l"},
		{"missing token", "pkcs11:module=/lib.so;label=l"},
		{"unknown attribute", "pkcs11:module=/lib.so;token=t;label=l;pin=1234"},
		{"duplicate attribute", "pkcs11:module=/lib.so;token=t;token=u;label=l"},
		{"component without value", "pkcs11:module=/lib.so;token=;label=l"},
		{"component without equals", "pkcs11:module=/lib.so;token;label=l"},
		{"empty body", "pkcs11:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := parsePKCS11Ref(tc.ref); err == nil {
				t.Fatalf("parsePKCS11Ref(%q) succeeded, want error", tc.ref)
			}
		})
	}
}
