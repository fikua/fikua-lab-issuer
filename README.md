# fikua-lab-issuer

OID4VCI credential issuer for the Fikua Lab EUDI Wallet ecosystem.

Standalone Go service (single binary, no dependency on `fikua-lab`'s Java
backend) that serves both the JSON/OID4VCI API and the issuance UI — same
shape as [`fikua-lab-attestation-registry`](https://github.com/fikua/fikua-lab-attestation-registry),
from which it fetches credential-scheme definitions (claims, display
metadata, format info) over HTTP instead of hardcoding them.

This is a rewrite of `fikua-lab`'s Java/Javalin `fikua-issuer` module
(`suite/backend/fikua-issuer`). Currently issues EUDI PID (SD-JWT VC +
mdoc); Student ID is not carried over from the Java service.

**HAIP-only**: this issuer implements a single protocol profile —
authorization_code via Pushed Authorization Requests (RFC 9126), DPoP
sender-constraining (RFC 9449), ATCA draft-07 client attestation, and
PKCE S256 are all mandatory on every request. There is no profile
selection and no pre-authorized_code/plain flow.

## Run

```sh
make run          # http://localhost:8080
```

## API

- `GET /.well-known/openid-credential-issuer` / `GET /.well-known/oauth-authorization-server` — OID4VCI / RFC 8414 metadata.
- `GET /oid4vci/v1/jwks` — issuer's public JWK Set.
- `POST /oid4vci/v1/issuance` — trigger an issuance, returns an authorization_code credential offer.
- `GET /oid4vci/v1/issuance` — paginated, sortable issuance record listing.
- `POST /oid4vci/v1/par` — Pushed Authorization Request.
- `GET /oid4vci/v1/authorize` — resolves a PAR request_uri into an authorization code (redirect).
- `POST /oid4vci/v1/token` — authorization_code grant, DPoP-bound.
- `POST /oid4vci/v1/nonce` — c_nonce issuance, DPoP-validated once a session exists.
- `POST /oid4vci/v1/credential` — credential issuance (SD-JWT VC or mdoc).
- `POST /oid4vci/v1/notification` — no-op per OID4VCI §10.1 (this issuer doesn't yet track notification_id).
- `GET /healthz` — health check (reports `degraded` if the attestation-registry catalogue refresh is stale).

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
