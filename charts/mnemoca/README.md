# MnemoCA Helm chart

Deploys [MnemoCA](https://github.com/MnemoShare/mnemoca), a post-quantum-ready
certificate authority (ML-DSA, hybrid, ACME, multi-tenant), using the
FIPS 140-3 enabled distroless image.

```bash
helm install mnemoca ./charts/mnemoca \
  --set externalUrl=https://ca.example.com \
  --set tls.existingSecret=mnemoca-tls
```

The defaults give a single-replica evaluation CA: embedded bolt store on a PVC,
chart-generated passphrase and self-signed listener certificate, root
bootstrapped as ML-DSA-87 with an ECDSA P-384 pair.

## Storage and high availability

| `store.type` | Replicas | State | Root bootstrap |
|---|---|---|---|
| `bolt` (default) | exactly 1 (the chart refuses anything else) | PVC, `Recreate` rollouts | `init` container |
| `mongo` | any | MongoDB (documents, key envelopes, audit chain) | pre-install/pre-upgrade hook Job |

`mongo` requires `store.mongo.uriSecret.name`, `passphrase.existingSecret` and `operatorApiKey.existingSecret`
(hooks run before chart-managed Secrets exist, and replicas must share the
passphrase). `replicaCount > 1` adds a PodDisruptionBudget and topology spread.

```bash
kubectl create secret generic mnemoca-passphrase --from-literal=passphrase="$(openssl rand -base64 48)"
kubectl create secret generic mnemoca-mongo --from-literal=uri='mongodb://...'
helm install mnemoca ./charts/mnemoca --set store.type=mongo --set replicaCount=3 \
  --set passphrase.existingSecret=mnemoca-passphrase --set operatorApiKey.existingSecret=mnemoca-operator-key --set store.mongo.uriSecret.name=mnemoca-mongo
```

## Root bootstrap

`mnemoca init --if-needed` runs on every install and upgrade and exits without
changes when a root already exists, so an existing root is never regenerated.
`init.*` values only matter on the first install.

## Secrets

No secret values live in `values.yaml`.

| Secret | Value | Notes |
|---|---|---|
| `passphrase.existingSecret` | key-encryption passphrase | bolt: generated once if unset, kept across upgrades and uninstall. Losing it loses the CA keys. |
| `operatorApiKey.existingSecret` | initial operator API key | required for `mongo` |
| `store.mongo.uriSecret` | MongoDB URI | required for `mongo` |
| `pkcs11.pinSecret` | HSM user PIN | required when `pkcs11.enabled` |
| `tls.existingSecret` | `kubernetes.io/tls` | listener certificate; self-signed if unset |

Generated Secrets use `lookup`, so they only stay stable when Helm can reach the
cluster (`helm install/upgrade`, not `helm template`).

## Operator API key

`operatorApiKey.existingSecret` is mounted as a file and adopted through
`MNEMOCA_BOOTSTRAP_API_KEY_FILE` on first start (format
`mnemoca_<16 hex>_<64 hex>`). It is required with `store.type=mongo`. With bolt
and no secret, the server mints a key into `/data/bootstrap-api-key` (0600).
The key is never written to the pod logs.

```bash
kubectl create secret generic mnemoca-operator-key \
  --from-literal=key="mnemoca_$(openssl rand -hex 8)_$(openssl rand -hex 32)"
```

## TLS and ingress

The server terminates TLS itself (`tls.enabled`, default on). Keep it
end-to-end: use `ssl-passthrough` (default annotations) or a TLS/TCP route
rather than terminating at the ingress.

## PKCS#11

Set `pkcs11.enabled` with `modulePath`, `tokenLabel`, `pinSecret`, and mount the
vendor module through `extraVolumes`/`extraVolumeMounts`. The default static
image cannot do PKCS#11; use a cgo build (see `docs/hsm.md`).

## Network policy

`networkPolicy.enabled` (default) allows ingress only from `ingressFrom` peers
(none by default, so set it) and egress to DNS, MongoDB, and optional
`hsmEgress` peers.

## Observability

The server exposes no metrics endpoint, so the chart ships no ServiceMonitor.
Liveness and readiness probe `GET /healthz`.

## Key values

See `values.yaml` for the full, commented list; `values.schema.json` validates
the main fields.
