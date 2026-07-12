package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"strings"

	"github.com/mnemoshare/mnemoca/internal/store"
)

// maxBodyBytes bounds ACME request bodies.
const maxBodyBytes = 1 << 20

// rawB64 is base64url without padding (RFC 8555 uses it everywhere).
func rawB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// flatJWS is a flattened JSON JWS (RFC 7515 §7.2.2, RFC 8555 §6.2).
type flatJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// jwsProtected is the ACME JWS protected header.
type jwsProtected struct {
	Alg   string          `json:"alg"`
	Nonce string          `json:"nonce"`
	URL   string          `json:"url"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
	KID   string          `json:"kid,omitempty"`
}

// jwsRequest is a verified ACME POST: the decoded payload plus the key that
// signed it — account-bound via kid, or a bare jwk (new-account/revoke-cert).
type jwsRequest struct {
	tenant  string
	payload []byte
	account *account // nil when authenticated by a bare jwk
	jwk     json.RawMessage
	key     crypto.PublicKey
	thumb   string // RFC 7638 SHA-256 thumbprint of jwk
}

// verifyRequest enforces RFC 8555 §6.2: application/jose+json flattened JWS,
// url binding, single-use nonce, exactly one of jwk/kid, and a valid
// signature by the presented key.
func (s *server) verifyRequest(r *http.Request, tenant string, allowJWK bool) (*jwsRequest, error) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/jose+json" {
		return nil, errf(http.StatusUnsupportedMediaType, "malformed", "content type must be application/jose+json")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return nil, errf(http.StatusBadRequest, "malformed", "reading request body: %v", err)
	}
	var jws flatJWS
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, errf(http.StatusBadRequest, "malformed", "invalid JWS: %v", err)
	}
	if jws.Protected == "" || jws.Signature == "" {
		return nil, errf(http.StatusBadRequest, "malformed", "JWS must carry protected and signature members")
	}
	protBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return nil, errf(http.StatusBadRequest, "malformed", "invalid protected header encoding: %v", err)
	}
	var hdr jwsProtected
	if err := json.Unmarshal(protBytes, &hdr); err != nil {
		return nil, errf(http.StatusBadRequest, "malformed", "invalid protected header: %v", err)
	}
	if hdr.URL != s.requestURL(r) {
		return nil, errf(http.StatusUnauthorized, "unauthorized", "JWS url %q does not match request URL %q", hdr.URL, s.requestURL(r))
	}
	ok, err := s.consumeNonce(tenant, hdr.Nonce)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errf(http.StatusBadRequest, "badNonce", "invalid or expired nonce")
	}

	req := &jwsRequest{tenant: tenant}
	switch {
	case len(hdr.JWK) > 0 && hdr.KID != "":
		return nil, errf(http.StatusBadRequest, "malformed", "JWS must carry exactly one of jwk or kid")
	case len(hdr.JWK) > 0:
		if !allowJWK {
			return nil, errf(http.StatusBadRequest, "malformed", "jwk authentication is not allowed on this endpoint")
		}
		req.jwk = hdr.JWK
	case hdr.KID != "":
		acct, err := s.accountByKID(tenant, hdr.KID)
		if err != nil {
			return nil, err
		}
		req.account = acct
		req.jwk = acct.JWK
	default:
		return nil, errf(http.StatusBadRequest, "malformed", "JWS must carry one of jwk or kid")
	}

	req.key, err = parseJWK(req.jwk)
	if err != nil {
		return nil, err
	}
	req.thumb, err = jwkThumbprint(req.jwk)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil {
		return nil, errf(http.StatusBadRequest, "malformed", "invalid signature encoding: %v", err)
	}
	if err := verifyJWSSignature(hdr.Alg, req.key, []byte(jws.Protected+"."+jws.Payload), sig); err != nil {
		return nil, err
	}

	req.payload, err = base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, errf(http.StatusBadRequest, "malformed", "invalid payload encoding: %v", err)
	}
	return req, nil
}

// accountByKID resolves a kid (which must be one of this tenant's account
// URLs) to a valid stored account.
func (s *server) accountByKID(tenant, kid string) (*account, error) {
	prefix := s.url(tenant, "/account/")
	if !strings.HasPrefix(kid, prefix) {
		return nil, errf(http.StatusBadRequest, "malformed", "kid %q is not an account URL of this tenant", kid)
	}
	id := strings.TrimPrefix(kid, prefix)
	var acct account
	if err := s.st.GetJSON(accountsBucket(tenant), id, &acct); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errf(http.StatusBadRequest, "accountDoesNotExist", "unknown account %q", id)
		}
		return nil, fmt.Errorf("acme: loading account: %w", err)
	}
	if acct.Status != statusValid {
		return nil, errf(http.StatusUnauthorized, "unauthorized", "account %s is %s", id, acct.Status)
	}
	return &acct, nil
}

// jwkFields is the union of the JWK members MnemoCA accepts (ADR-0007:
// ES256, RS256, EdDSA account keys).
type jwkFields struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseJWK decodes a public JWK into a stdlib public key.
func parseJWK(raw json.RawMessage) (crypto.PublicKey, error) {
	var k jwkFields
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, errf(http.StatusBadRequest, "badPublicKey", "invalid JWK: %v", err)
	}
	dec := func(s, name string) ([]byte, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, errf(http.StatusBadRequest, "badPublicKey", "invalid JWK %s member: %v", name, err)
		}
		return b, nil
	}
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, errf(http.StatusBadRequest, "badPublicKey", "unsupported EC curve %q (P-256 only)", k.Crv)
		}
		x, err := dec(k.X, "x")
		if err != nil {
			return nil, err
		}
		y, err := dec(k.Y, "y")
		if err != nil {
			return nil, err
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errf(http.StatusBadRequest, "badPublicKey", "P-256 coordinates must be 32 bytes")
		}
		point := make([]byte, 0, 65)
		point = append(point, 4) // uncompressed
		point = append(point, x...)
		point = append(point, y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return nil, errf(http.StatusBadRequest, "badPublicKey", "invalid P-256 point: %v", err)
		}
		return pub, nil
	case "RSA":
		n, err := dec(k.N, "n")
		if err != nil {
			return nil, err
		}
		e, err := dec(k.E, "e")
		if err != nil {
			return nil, err
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() || eInt.Int64() <= 1 {
			return nil, errf(http.StatusBadRequest, "badPublicKey", "invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, errf(http.StatusBadRequest, "badPublicKey", "unsupported OKP curve %q", k.Crv)
		}
		x, err := dec(k.X, "x")
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errf(http.StatusBadRequest, "badPublicKey", "invalid Ed25519 key length %d", len(x))
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, errf(http.StatusBadRequest, "badPublicKey", "unsupported key type %q", k.Kty)
	}
}

// jwkThumbprint computes the RFC 7638 SHA-256 thumbprint of a public JWK:
// the hash of the canonical JSON containing only the required members in
// lexicographic order.
func jwkThumbprint(raw json.RawMessage) (string, error) {
	var k jwkFields
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", errf(http.StatusBadRequest, "badPublicKey", "invalid JWK: %v", err)
	}
	var canon string
	switch k.Kty {
	case "EC":
		canon = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, k.Crv, k.X, k.Y)
	case "RSA":
		canon = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, k.E, k.N)
	case "OKP":
		canon = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, k.Crv, k.X)
	default:
		return "", errf(http.StatusBadRequest, "badPublicKey", "unsupported key type %q", k.Kty)
	}
	sum := sha256.Sum256([]byte(canon))
	return rawB64(sum[:]), nil
}

// verifyJWSSignature checks sig over signingInput for the declared JWS alg.
func verifyJWSSignature(alg string, key crypto.PublicKey, signingInput, sig []byte) error {
	switch alg {
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return errf(http.StatusBadRequest, "badSignatureAlgorithm", "ES256 requires a P-256 EC key")
		}
		if len(sig) != 64 {
			return errf(http.StatusBadRequest, "malformed", "ES256 signature must be 64 bytes, got %d", len(sig))
		}
		h := sha256.Sum256(signingInput)
		r := new(big.Int).SetBytes(sig[:32])
		ss := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, h[:], r, ss) {
			return errf(http.StatusUnauthorized, "unauthorized", "JWS signature verification failed")
		}
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errf(http.StatusBadRequest, "badSignatureAlgorithm", "RS256 requires an RSA key")
		}
		h := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
			return errf(http.StatusUnauthorized, "unauthorized", "JWS signature verification failed")
		}
	case "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return errf(http.StatusBadRequest, "badSignatureAlgorithm", "EdDSA requires an Ed25519 key")
		}
		if !ed25519.Verify(pub, signingInput, sig) {
			return errf(http.StatusUnauthorized, "unauthorized", "JWS signature verification failed")
		}
	default:
		return errf(http.StatusBadRequest, "badSignatureAlgorithm", "unsupported JWS algorithm %q (ES256, RS256, EdDSA)", alg)
	}
	return nil
}
