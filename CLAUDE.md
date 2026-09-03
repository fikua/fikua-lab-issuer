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

## Migration plan / phasing

See the plan this rewrite follows (phases 1-4: skeleton+pipeline →
registry-client integration → full OID4VCI flow parity → cutover) —
ask the user for the current plan file if picking this up mid-migration,
or check recent commits/PRs for which phase is in progress.

## Architecture (target shape, fills in across phases)

```text
cmd/issuer/              entrypoint: wiring only, no logic
internal/config/         env var loading
internal/registryclient/ HTTP client for fikua-lab-attestation-registry + cache/refresh
internal/credentialconfig/ AttestationScheme -> OID4VCI credential_configurations_supported
internal/oid4vci/        metadata, offer, request/response, proof validator
internal/oauth2/         DPoP, client attestation (ATCA), PKCE, error model
internal/crypto/         signing key (EC P-256/ES256), JWK, PEM loader
internal/sdjwt/          SD-JWT builder
internal/mdoc/           mdoc builder (ISO 18013-5, CBOR)
internal/profile/        ProfileConfig (issuer-relevant fields) + Postgres store
internal/issuance/       OID4VCI flows (pre-auth, authz-code/HAIP, PAR, DPoP, wallet-initiated)
internal/session/        in-memory session store (tokens, nonces, PAR requests, ...)
internal/email/          EmailService (Resend + NoOp)
internal/httpapi/        JSON API — /oid4vci/v1/*, well-known endpoints
internal/webui/          serves the embedded static UI
web/static/              UI assets (HTML/CSS/JS), embedded into the binary
```

Currently only `internal/httpapi` (health check) and `internal/webui`
exist — everything else lands in later phases.

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
