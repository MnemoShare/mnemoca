# HSM (PKCS#11) signing backend

MnemoCA can hold CA private keys on a PKCS#11 token — SoftHSM2, YubiHSM2,
AWS CloudHSM, Thales Luna, and other conformant HSMs — via the `pkcs11`
signing backend (ADR-0005). Private keys are generated on-token with
`CKA_SENSITIVE` and `CKA_EXTRACTABLE=false`; all signing happens inside the
HSM and key material never enters MnemoCA's memory.

## Requirements

- **A cgo-enabled build.** The backend uses
  [ThalesGroup/crypto11](https://github.com/ThalesGroup/crypto11), which loads
  the vendor's PKCS#11 module with `dlopen` and therefore requires
  `CGO_ENABLED=1`. Static `CGO_ENABLED=0` binaries (including the FIPS Docker
  image) still compile and run, but every PKCS#11 key operation returns a
  clear "requires a cgo-enabled build" error. Use the `softkey` backend
  there, or build a cgo variant of the image for HSM deployments.
- The vendor's PKCS#11 module (`.so`) installed on the host, and a token
  initialized with a user PIN.

## Configuration

| Env var | `PKCS11Config` field | Meaning |
|---|---|---|
| `MNEMOCA_PKCS11_MODULE` | `ModulePath` | Path to the PKCS#11 module, e.g. `/usr/lib/softhsm/libsofthsm2.so` |
| `MNEMOCA_PKCS11_TOKEN` | `TokenLabel` | Token label (`CKA_LABEL`) to open |
| `MNEMOCA_PKCS11_PIN` | `PIN` | User PIN for the token |

> Env wiring note: `internal/signer` exposes `NewPKCS11(PKCS11Config)`; the
> actual `env.go` wiring that reads these variables and registers the backend
> lands after this feature merges, by design, to keep this change confined to
> the signer package.

The module is loaded lazily: constructing the backend is cheap and connects
to the HSM only on the first key operation.

### Key references

Keys are addressed by a persistable `KeyRef`:

```
pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=mnemoca;label=root-2026
```

`module` and `token` pin the ref to a specific HSM configuration (opening a
ref against a differently configured backend fails loudly), and `label` is
the on-token `CKA_LABEL`/`CKA_ID` of the key pair. **The PIN is never part of
the reference** — refs are persisted in CA metadata; the PIN comes only from
configuration.

## Supported algorithms

| Algorithm | Status |
|---|---|
| ECDSA P-256 (`ecdsa-p256`) | Supported, generated and signed on-token |
| ECDSA P-384 (`ecdsa-p384`) | Supported, generated and signed on-token |
| Ed25519 | Not available: crypto11 does not implement `CKM_EC_EDWARDS_KEY_PAIR_GEN`; use ECDSA on-token or `softkey` |
| ML-DSA-44/65/87 | Not yet — see below |
| Composite (draft-19) | Not supported on tokens; use `softkey` |

### ML-DSA status

PKCS#11 3.2 (OASIS, 2025) standardizes ML-DSA mechanisms (`CKM_ML_DSA`,
`CKM_ML_DSA_KEY_PAIR_GEN`), but neither the crypto11 library nor SoftHSM2
implements them yet, and shipping HSM firmware support is still sparse.
Until that lands, `Generate` for any ML-DSA algorithm on the `pkcs11`
backend returns an error directing you to the software backends. Keep
ML-DSA keys in `softkey` (AES-256-GCM encrypted at rest, scrypt-derived
KEK) for now; the backend interface (ADR-0005) already
carries the message-vs-digest distinction ML-DSA needs, so on-token ML-DSA
is additive once library and firmware support exist.

### Mixed backends

MnemoCA resolves each key's backend from its `KeyRef` scheme, so one CA
hierarchy can span backends. A recommended hybrid posture today:

- **Root pair (classical): HSM.** `pkcs11:…;label=root-ecdsa-p384` — the
  long-lived, high-value classical key lives in hardware.
- **ML-DSA keys: software.** `softkey:roots/root-mldsa87.key` — the
  post-quantum keys stay in encrypted software storage until HSM ML-DSA
  support matures, then migrate.

## SoftHSM2 quickstart (dev/test)

```sh
# Install
brew install softhsm            # macOS (module: $(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so)
apt-get install softhsm2        # Debian/Ubuntu (module: /usr/lib/softhsm/libsofthsm2.so)

# Optional: point SoftHSM at a scratch token store
cat > /tmp/softhsm2.conf <<EOF
directories.tokendir = /tmp/softhsm-tokens
objectstore.backend = file
EOF
mkdir -p /tmp/softhsm-tokens
export SOFTHSM2_CONF=/tmp/softhsm2.conf

# Initialize a token
softhsm2-util --init-token --free --label mnemoca --pin 1234 --so-pin 12345678

# Configure MnemoCA
export MNEMOCA_PKCS11_MODULE=$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so
export MNEMOCA_PKCS11_TOKEN=mnemoca
export MNEMOCA_PKCS11_PIN=1234
```

The signer package's tests (`internal/signer/pkcs11_test.go`) run this exact
flow against a throwaway token and skip with a reason if SoftHSM2 is not
installed.

## Production HSM notes

### YubiHSM2

Install the YubiHSM2 SDK and run `yubihsm-connector`; the PKCS#11 module is
`yubihsm_pkcs11.so` (typically `/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so`
or `/usr/local/lib/pkcs11/yubihsm_pkcs11.so` on macOS). The module reads
`YUBIHSM_PKCS11_CONF` for the connector URL:

```
export MNEMOCA_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
# yubihsm_pkcs11.conf: connector = http://127.0.0.1:12345
```

The YubiHSM2 presents a single token; the PIN is `<auth-key-id><password>`
per Yubico's PKCS#11 documentation.

### AWS CloudHSM

Install the CloudHSM PKCS#11 client package; the module is
`/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`. The PIN is the CloudHSM crypto
user credential in `<CU user>:<password>` form. Ensure the instance can reach
the cluster HSM ENIs and `cloudhsm-client` is running.

### Kubernetes

Deliver `MNEMOCA_PKCS11_PIN` as a Kubernetes Secret (consistent with the
`softkey` passphrase posture) and mount the vendor module into the MnemoCA
container image. Remember: the container must be a cgo build.
