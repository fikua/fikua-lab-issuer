# Fikua Lab — Issuer

OID4VCI Issuer frontend for the Fikua Lab. Served at
**<https://issuer.lab.fikua.com>**.

The static UI talks to the lab backend over `/oid4vci/v1/*` and
`/.well-known/*`. The issuer URL (`https://issuer.lab.fikua.com`) is
the **Credential Issuer identifier** referenced by every credential
offer, every `.well-known/openid-credential-issuer` document, and every
verifier that trusts it — so the hostname is part of the spec, not just
DNS convenience (see ADR 0008).

## What lives here

```text
.
├── index.html      Issuer UI
├── style.css
├── app.js
├── favicon.svg
└── shared/         Vendored shared assets (consent banner, error pages)
```

Pure static — no build step.

## Hosting

- **Production:** Cloudflare Workers Static Assets (project
  `fikua-lab-issuer`), custom domain `issuer.lab.fikua.com`.
- **Backend reverse-proxy:** `/.well-known/*`, `/oid4vci/v1/*` and
  `/health` are proxied to the lab backend at the edge (Cloudflare
  Worker / Page Rule), which speaks the OID4VCI protocol.

## Architecture decisions

- ADR 0008 — Fikua Lab frontends on Cloudflare Workers.

## License

Apache-2.0. See [LICENSE](LICENSE).
