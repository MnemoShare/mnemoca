# ADR-0009: Open source under Apache-2.0; CLI split between mnemoca and mnemocli

**Status:** Accepted
**Date:** 2026-07-11

## Context

MnemoCA is to be released open source, like `keycloak-mcp`. It must be adoptable
by non-MnemoShare users (the trust argument for a CA is strongest when the code
is public), while MnemoShare's platform integrates it natively. Two CLIs are in
play: this repo's own tool, and MnemoShare's existing `mnemocli` (cobra-based,
`app/cmd/mnemocli/`).

## Decision

- **License: Apache-2.0** (patent grant matters for crypto software; matches
  ecosystem norms — Kubernetes, cert-manager, Vault-era tooling — and is
  friendlier to regulated adopters than copyleft).
- **Repo layout supports standalone adoption:** everything needed to run a CA
  lives in this repo (`mnemoca` binary, Helm chart in Phase 5, docs). No imports
  from MnemoShare private code. The public Go client lives at `pkg/mnemoca`.
- **`mnemoca` (this repo):** the simple, complete, open-source CLI —
  `init`, `serve`, `tenant`, `profile`, `issue`, `sign`, `revoke`, `crl`,
  `inspect`, `token`/`eab`, `audit verify`, `version`. cobra, matching mnemocli
  conventions.
- **`mnemocli ca …` (app repo, Phase 4):** thin subcommands over `pkg/mnemoca`
  for operators already living in mnemocli (status, issue, revoke, certs,
  tenants). No CA business logic in the app repo.
- Public GitHub repo `MnemoShare/mnemoca`, developed in the monorepo
  (`mnemoshare-ca/`) and mirrored out like `e2e-tests`, with GHCR image
  `ghcr.io/mnemoshare/mnemoca`. Release signing follows the app's release
  workflow standards (no manual pushes).

## Consequences

- (+) Auditability sells the CA; community issue reports harden security-critical
  code; Apache-2.0 removes adoption friction for the customers we target.
- (+) One source of truth for CA logic; both CLIs are thin clients over the same
  API/library.
- (−) Public code means public vulnerability surface — Phase 5 requires a
  SECURITY.md, coordinated disclosure policy, and release-signing before the
  repo goes public.
