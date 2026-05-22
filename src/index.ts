/**
 * Cloudflare Worker for lab.fikua.com/issuer/*.
 *
 * Serves the static issuer UI (and the absorbed identify sub-page) for any
 * non-API path. For API paths (.well-known/, oid4vci/, oauth/, health) the
 * /issuer prefix is stripped and the request is forwarded to the lab
 * backend at https://lab-backend.fikua.com (Cloudflare Tunnel + Access
 * Service Auth), attaching the CF-Access service-token headers so the
 * Access policy lets it through.
 */

export interface Env {
    ASSETS: Fetcher;
    LAB_BACKEND_ORIGIN: string;
    CF_ACCESS_CLIENT_ID: string;
    CF_ACCESS_CLIENT_SECRET: string;
}

const ROLE_PREFIX = '/issuer';

// Paths (relative to ROLE_PREFIX) that must reach the backend instead of
// the static bundle.
const BACKEND_PREFIXES = [
    '/.well-known/',
    '/oid4vci/',
    '/oauth/',
    '/health',
];

function matchesBackend(relativePath: string): boolean {
    return BACKEND_PREFIXES.some((p) =>
        p.endsWith('/')
            ? relativePath.startsWith(p)
            : relativePath === p || relativePath.startsWith(p + '/'),
    );
}

async function proxyToBackend(request: Request, env: Env, relativePath: string): Promise<Response> {
    const url = new URL(request.url);
    const upstream = new URL(relativePath + url.search, env.LAB_BACKEND_ORIGIN);
    const headers = new Headers(request.headers);
    headers.set('CF-Access-Client-Id', env.CF_ACCESS_CLIENT_ID);
    headers.set('CF-Access-Client-Secret', env.CF_ACCESS_CLIENT_SECRET);
    return fetch(upstream.toString(), {
        method: request.method,
        headers,
        body: ['GET', 'HEAD'].includes(request.method)
            ? undefined
            : await request.clone().arrayBuffer(),
        redirect: 'manual',
    });
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);
        const relative = url.pathname.startsWith(ROLE_PREFIX)
            ? url.pathname.slice(ROLE_PREFIX.length) || '/'
            : url.pathname;

        if (matchesBackend(relative)) {
            return proxyToBackend(request, env, relative);
        }
        return env.ASSETS.fetch(request);
    },
};
