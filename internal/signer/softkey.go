package signer

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/mldsa"
	mldsax509 "filippo.io/mldsa/x509"
	"golang.org/x/crypto/scrypt"

	"github.com/mnemoshare/mnemoca/internal/pkix"
)

// Softkey stores keys as individual files encrypted with AES-256-GCM under a
// scrypt-derived key (ADR-0005). Suitable for dev and for deployments where
// the passphrase arrives via Kubernetes Secret; production roots belong in an
// HSM/KMS backend.
type Softkey struct {
	dir        string
	passphrase []byte
}

// NewSoftkey creates a softkey backend rooted at dir.
func NewSoftkey(dir string, passphrase []byte) (*Softkey, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("softkey: empty passphrase")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Softkey{dir: dir, passphrase: passphrase}, nil
}

func (s *Softkey) Name() string { return "softkey" }

// envelope is the on-disk format: scrypt(N,r,p, salt) -> AES-256-GCM.
type envelope struct {
	Version    int            `json:"version"`
	Algorithm  pkix.Algorithm `json:"algorithm"`
	KDF        string         `json:"kdf"`
	ScryptN    int            `json:"scrypt_n"`
	ScryptR    int            `json:"scrypt_r"`
	ScryptP    int            `json:"scrypt_p"`
	Salt       []byte         `json:"salt"`
	Nonce      []byte         `json:"nonce"`
	Ciphertext []byte         `json:"ciphertext"`
}

const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

type softSigner struct {
	crypto.Signer
	alg pkix.Algorithm
}

func (s *softSigner) Algorithm() pkix.Algorithm { return s.alg }

func (s *Softkey) path(ref KeyRef) (string, error) {
	rel := strings.TrimPrefix(string(ref), "softkey:")
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("softkey: invalid key reference %q", ref)
	}
	return filepath.Join(s.dir, clean), nil
}

// Generate creates a new key for alg, stores it encrypted under label, and
// returns an open Signer plus its reference.
func (s *Softkey) Generate(_ context.Context, alg pkix.Algorithm, label string) (Signer, KeyRef, error) {
	key, err := pkix.GenerateKey(alg)
	if err != nil {
		return nil, "", err
	}
	material, err := marshalKeyMaterial(key)
	if err != nil {
		return nil, "", err
	}
	defer zero(material)

	ref := KeyRef("softkey:" + label + ".key")
	path, err := s.path(ref)
	if err != nil {
		return nil, "", err
	}
	if _, err := os.Stat(path); err == nil {
		return nil, "", fmt.Errorf("softkey: key %q already exists", label)
	}

	env, err := s.seal(alg, material)
	if err != nil {
		return nil, "", err
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, "", err
	}
	return &softSigner{Signer: key, alg: alg}, ref, nil
}

// Open loads and decrypts the key at ref.
func (s *Softkey) Open(_ context.Context, ref KeyRef) (Signer, error) {
	path, err := s.path(ref)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("softkey: %w", err)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("softkey: corrupt envelope: %w", err)
	}
	material, err := s.unseal(&env)
	if err != nil {
		return nil, err
	}
	defer zero(material)
	key, err := unmarshalKeyMaterial(env.Algorithm, material)
	if err != nil {
		return nil, err
	}
	return &softSigner{Signer: key, alg: env.Algorithm}, nil
}

// Destroy overwrites and removes the key file.
func (s *Softkey) Destroy(_ context.Context, ref KeyRef) error {
	path, err := s.path(ref)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	// Best-effort overwrite before unlink.
	junk := make([]byte, info.Size())
	if _, err := rand.Read(junk); err == nil {
		_ = os.WriteFile(path, junk, 0o600)
	}
	return os.Remove(path)
}

func (s *Softkey) seal(alg pkix.Algorithm, plaintext []byte) (*envelope, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	kek, err := scrypt.Key(s.passphrase, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &envelope{
		Version:   1,
		Algorithm: alg,
		KDF:       "scrypt",
		ScryptN:   scryptN, ScryptR: scryptR, ScryptP: scryptP,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plaintext, []byte(alg)),
	}, nil
}

func (s *Softkey) unseal(env *envelope) ([]byte, error) {
	if env.KDF != "scrypt" || env.Version != 1 {
		return nil, fmt.Errorf("softkey: unsupported envelope version/KDF")
	}
	kek, err := scrypt.Key(s.passphrase, env.Salt, env.ScryptN, env.ScryptR, env.ScryptP, 32)
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, env.Nonce, env.Ciphertext, []byte(env.Algorithm))
	if err != nil {
		return nil, fmt.Errorf("softkey: decryption failed (wrong passphrase or tampered file)")
	}
	return plaintext, nil
}

// marshalKeyMaterial serializes private key material: ML-DSA as its 32-byte
// seed (RFC 9881 preference), classical as PKCS#8, composite as
// seed || uint16-length-prefixed PKCS#8 of the traditional component.
func marshalKeyMaterial(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *mldsa.PrivateKey:
		return k.Bytes(), nil
	case *pkix.CompositeKey:
		tradDER, err := mldsax509.MarshalPKCS8PrivateKey(tradPrivate(k.Trad))
		if err != nil {
			return nil, err
		}
		seed := k.MLDSA.Bytes()
		out := make([]byte, 0, len(seed)+2+len(tradDER))
		out = append(out, seed...)
		out = append(out, byte(len(tradDER)>>8), byte(len(tradDER)))
		out = append(out, tradDER...)
		return out, nil
	default:
		return mldsax509.MarshalPKCS8PrivateKey(tradPrivate(key))
	}
}

// tradPrivate unwraps a crypto.Signer to the concrete private key type the
// PKCS#8 marshaler expects.
func tradPrivate(s crypto.Signer) any { return s }

func unmarshalKeyMaterial(alg pkix.Algorithm, material []byte) (crypto.Signer, error) {
	info, err := pkix.Lookup(alg)
	if err != nil {
		return nil, err
	}
	switch {
	case info.Hybrid:
		if len(material) < mldsa.PrivateKeySize+2 {
			return nil, fmt.Errorf("softkey: composite key material too short")
		}
		seed := material[:mldsa.PrivateKeySize]
		rest := material[mldsa.PrivateKeySize:]
		tradLen := int(rest[0])<<8 | int(rest[1])
		if len(rest) != 2+tradLen {
			return nil, fmt.Errorf("softkey: composite key material length mismatch")
		}
		var mldsaAlg pkix.Algorithm
		switch alg {
		case pkix.CompositeMLDSA65ECDSAP256:
			mldsaAlg = pkix.MLDSA65
		case pkix.CompositeMLDSA44Ed25519:
			mldsaAlg = pkix.MLDSA44
		default:
			return nil, fmt.Errorf("softkey: unknown composite %q", alg)
		}
		mk, err := pkix.NewMLDSAPrivateKey(mldsaAlg, seed)
		if err != nil {
			return nil, err
		}
		tradAny, err := mldsax509.ParsePKCS8PrivateKey(rest[2:])
		if err != nil {
			return nil, err
		}
		trad, ok := tradAny.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("softkey: traditional component is not a signer")
		}
		return pkix.NewCompositeKey(alg, mk.(*mldsa.PrivateKey), trad)
	case info.PQ:
		return pkix.NewMLDSAPrivateKey(alg, material)
	default:
		keyAny, err := mldsax509.ParsePKCS8PrivateKey(material)
		if err != nil {
			return nil, err
		}
		key, ok := keyAny.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("softkey: parsed key is not a signer")
		}
		return key, nil
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
