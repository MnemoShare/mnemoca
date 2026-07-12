// PKCS#11 HSM backend: configuration and KeyRef scheme shared by both the
// cgo implementation (pkcs11_cgo.go) and the non-cgo stub (pkcs11_nocgo.go).
//
// KeyRef scheme:
//
//	pkcs11:module=/path/lib.so;token=<token-label>;label=<key-label>
//
// The PIN is deliberately NOT part of the reference: refs are persisted in CA
// metadata, and secrets never belong there. The PIN arrives via configuration
// (env MNEMOCA_PKCS11_PIN).
package signer

import (
	"fmt"
	"strings"
)

// PKCS11Config configures the PKCS#11 HSM backend.
type PKCS11Config struct {
	// ModulePath is the PKCS#11 module shared library, e.g.
	// /opt/homebrew/lib/softhsm/libsofthsm2.so (env MNEMOCA_PKCS11_MODULE).
	ModulePath string
	// TokenLabel selects the token by its CKA_LABEL
	// (env MNEMOCA_PKCS11_TOKEN).
	TokenLabel string
	// PIN is the user PIN used to log in to the token
	// (env MNEMOCA_PKCS11_PIN). Never embedded in KeyRefs.
	PIN string
}

const pkcs11Scheme = "pkcs11"

// formatPKCS11Ref builds the canonical pkcs11 KeyRef for a key. Components
// may not be empty or contain ';' (the attribute separator); '=' is allowed
// in values because parsing splits on the first '=' only.
func formatPKCS11Ref(module, token, label string) (KeyRef, error) {
	for _, c := range []struct{ name, val string }{
		{"module", module}, {"token", token}, {"label", label},
	} {
		if c.val == "" {
			return "", fmt.Errorf("pkcs11: key reference %s must not be empty", c.name)
		}
		if strings.Contains(c.val, ";") {
			return "", fmt.Errorf("pkcs11: key reference %s %q must not contain ';'", c.name, c.val)
		}
	}
	return KeyRef(fmt.Sprintf("%s:module=%s;token=%s;label=%s", pkcs11Scheme, module, token, label)), nil
}

// parsePKCS11Ref decodes a pkcs11 KeyRef produced by formatPKCS11Ref.
func parsePKCS11Ref(ref KeyRef) (module, token, label string, err error) {
	if ref.Scheme() != pkcs11Scheme {
		return "", "", "", fmt.Errorf("pkcs11: not a pkcs11 key reference: %q", ref)
	}
	body := strings.TrimPrefix(string(ref), pkcs11Scheme+":")
	seen := make(map[string]bool, 3)
	for _, part := range strings.Split(body, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok || v == "" {
			return "", "", "", fmt.Errorf("pkcs11: malformed component %q in key reference %q", part, ref)
		}
		if seen[k] {
			return "", "", "", fmt.Errorf("pkcs11: duplicate attribute %q in key reference %q", k, ref)
		}
		seen[k] = true
		switch k {
		case "module":
			module = v
		case "token":
			token = v
		case "label":
			label = v
		default:
			return "", "", "", fmt.Errorf("pkcs11: unknown attribute %q in key reference %q", k, ref)
		}
	}
	if module == "" || token == "" || label == "" {
		return "", "", "", fmt.Errorf("pkcs11: key reference %q must carry module, token, and label", ref)
	}
	return module, token, label, nil
}
