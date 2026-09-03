# fikua-lab-issuer

OID4VCI credential issuer for the Fikua Lab EUDI Wallet ecosystem.

Standalone Go service (single binary, no dependency on `fikua-lab`'s Java
backend) that serves both the JSON/OID4VCI API and the issuance UI — same
shape as [`fikua-lab-attestation-registry`](https://github.com/fikua/fikua-lab-attestation-registry),
from which it fetches credential-scheme definitions (claims, display
metadata, format info) over HTTP instead of hardcoding them.

This is a rewrite of `fikua-lab`'s Java/Javalin `fikua-issuer` module
(`suite/backend/fikua-issuer`) — see the migration plan for phasing.
Currently issues EUDI PID (SD-JWT VC + mdoc); Student ID is not carried
over from the Java service.

## Run

```sh
make run          # http://localhost:8080
```

## API

Phase 1: only `/healthz`. OID4VCI endpoints (`/.well-known/*`,
`/oid4vci/v1/*`) land in later phases — see the migration plan.

## UI

`/` serves the issuance UI (credential picker, issuance form, records
browser) — plain HTML/CSS/JS, no build step, ported as-is from the
previous Cloudflare Worker frontend.

## Build

```sh
make build        # bin/issuer, static binary, no CGO
```

Docker image is built `FROM scratch` — no runtime dependencies, single
static binary.

## Deployment

CI/CD mirrors `fikua-lab-attestation-registry`'s pipeline:

1. `build.yml` — vet/build/test on every push and PR.
2. `release.yml` — on push to `main` or a published release, builds a
   multi-arch image and pushes `docker.io/fikua/fikua-lab-issuer` to
   Docker Hub.
3. `deploy.yml` — manually dispatched, or auto-triggered by a published
   release (gated behind the `prd` GitHub Environment's required
   reviewers). SSHes into the VPS through a Cloudflare Access tunnel,
   syncs `compose.yaml` to `/opt/vps/projects/fikua-lab-issuer/`, runs
   `docker compose pull && up -d`, then polls `/healthz`.

Public at `https://issuer.fikua.com` — a plain Cloudflare-proxied A
record straight to Traefik, same pattern as `fikua-lab-attestation-registry`.
No Cloudflare Access, no Tunnel, no Worker in front.

Required repo secrets (same as `fikua-lab-attestation-registry`):
`DOCKER_USERNAME`, `DOCKER_TOKEN`, `VPS_SSH_PRIVATE_KEY`,
`CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`.

## License

Apache-2.0. See [LICENSE](LICENSE).
