# fikua-lab-issuer — Project Guide

## Purpose

OID4VCI credential issuer for the Fikua Lab EUDI Wallet ecosystem. This is
a Go rewrite of `fikua-lab`'s Java/Javalin `fikua-issuer` module
(`suite/backend/fikua-issuer`), merging its UI and backend into a single
deployable Go binary — the same shape as
[`fikua-lab-attestation-registry`](https://github.com/fikua/fikua-lab-attestation-registry).

**Why a rewrite and not a merge:** the Java module lives in a
Java/Gradle/Javalin monorepo; there is no Go code to fuse it with. The
previous `fikua-lab-issuer` repo was a Cloudflare-Worker-only static
frontend with zero backend of its own — see git history on `main` prior
to this rewrite.

**Independence from `fikua-lab-attestation-registry`:** this service
fetches credential-scheme definitions (claims, display metadata,
vct/docType, supported formats) from that registry's `/api/v1/schemes`
API at runtime, rather than hardcoding them (as the Java service does
today in `IssuanceService.buildCredentialConfigurations()`). No shared
Go module, no shared code — only the JSON API contract, to keep the two
services independently deployable.

**Student ID is not carried over.** The Java service also issues a
Student ID credential (EWC ds010); this rewrite drops it — PID
(SD-JWT VC + mdoc) only.

**HAIP-only, no profile system.** The Java service supports multiple
protocol profiles (a "plain" pre-authorized_code flow and a HAIP
authorization_code flow, selected via a Postgres-backed `ProfileConfig`).
This rewrite implements HAIP only: authorization_code via PAR, DPoP,
ATCA client attestation, and PKCE S256 are always mandatory. There is no
profile selection, no pre-authorized_code grant, and no
`internal/profile` package — this was a deliberate simplification, not an
oversight.

## Status

Full OID4VCI/HAIP flow parity is implemented and verified end-to-end
against a simulated wallet (PAR → authorize → token → nonce → credential,
for both PID sd-jwt and mdoc). Issuance records persist to Postgres when
`FIKUA_DB_URL` is set (falls back to an in-memory store otherwise — fine
for local dev, not for a real deployment). Signing can be local (PEM/
ephemeral, `internal/crypto.LoadOrGenerate`) or remote via a Fikua Digital
Signature Service CSC v2.0 instance (`internal/cscclient`, when
`FIKUA_DSS_URL` is set). What remains before a production cutover:
pointing the real `issuer.fikua.com` hostname/DNS at this service instead
of the Java issuer.

## Architecture

```text
cmd/issuer/                entrypoint: wiring only, no logic
internal/config/           env var loading
internal/registryclient/   HTTP client for fikua-lab-attestation-registry + cache/refresh
internal/credentialconfig/ AttestationScheme -> OID4VCI credential_configurations_supported
internal/oid4vci/          metadata, offer, request/response, proof validator
internal/oauth2/           DPoP, client attestation (ATCA), PKCE, error model
internal/crypto/           signing key abstraction (local EC P-256/ES256 or remote crypto.Signer), JWK, PEM loader, wallet-provider trust anchor
internal/cscclient/        Fikua DSS (CSC v2.0) client — remote signing backend for internal/crypto
internal/sdjwt/            SD-JWT builder
internal/mdoc/             mdoc builder (ISO 18013-5, CBOR)
internal/issuance/         HAIP OID4VCI flow: PAR, authorize, authorization_code token, nonce, credential, issuance listing; Postgres or in-memory record store
internal/session/          in-memory session store (PAR requests, auth codes, access tokens, nonces)
internal/httpapi/          JSON API — /oid4vci/v1/*, well-known endpoints
internal/webui/            serves the embedded static UI
web/static/                UI assets (HTML/CSS/JS), embedded into the binary
db/                        embedded Postgres schema (schema.sql), applied idempotently at boot — no external migration tool
```

## Conventions

- `gofmt` and `go vet` clean before every commit.
- No framework — standard library only (`net/http`, `embed`), matching
  `fikua-lab-attestation-registry`'s stance. Keep it that way unless a
  real need appears.
- Do not duplicate credential/claims definitions locally — fetch from
  `fikua-lab-attestation-registry`. If a scheme is missing there, add it
  to that registry first; don't add a local fallback table (this was
  weighed and rejected during planning — it recreates the exact
  hardcoding problem the registry exists to solve).

## Language

- Code, comments, commit messages: English.
- Communication with the user: Catalan, Spanish, or English as they prefer.

## Deployment

CI/CD (`.github/workflows/`) mirrors `fikua-lab-attestation-registry`'s
pipeline exactly: `build.yml` (vet/test) → `release.yml` (multi-arch
Docker Hub push) → `deploy.yml` (SSH via Cloudflare Access tunnel *for
VPS access only*, `docker compose pull && up -d`, health poll, Traefik
smoke test).

Public at `issuer.fikua.com` — a plain Cloudflare-proxied A record
straight to Traefik, same pattern as `fikua-lab-attestation-registry`.
No Tunnel, no Cloudflare Access, no Worker in front.

The deployment definition (`compose.yaml`) should be sourced from
`fikua-platform-iac/projects/fikua-lab-issuer/` once that exists, synced
into this repo's own `compose.yaml` so `deploy.yml` can `scp` it — same
convention as `fikua-lab-attestation-registry` and `niu`.
