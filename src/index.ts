/**
 * Cloudflare Worker for issuer.lab.fikua.com.
 *
 * The frontend (app.js) issues calls to /oid4vci/v1/* and /.well-known/*
 * which must reach the Fikua Lab backend rather than serving the static
 * index.html. We proxy those prefixes to api.lab.fikua.com (Traefik on
 * the VPS routes that hostname to the fikua-lab container).
 *
 * Anything else falls through to the static asset binding.
 */

export interface Env {
    ASSETS: Fetcher;
}

const BACKEND_ORIGIN = 'https://api.lab.fikua.com';

// Prefixes that must reach the backend instead of the static bundle.
const BACKEND_PREFIXES = [
    '/.well-known/',
    '/oid4vci/',
    '/health',
];

function isBackendPath(pathname: string): boolean {
    return BACKEND_PREFIXES.some((p) =>
        p.endsWith('/') ? pathname.startsWith(p) : pathname === p || pathname.startsWith(p + '/'),
    );
}

async function proxyToBackend(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const upstream = new URL(BACKEND_ORIGIN + url.pathname + url.search);
    const init: RequestInit = {
        method: request.method,
        headers: request.headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.clone().arrayBuffer(),
        redirect: 'manual',
    };
    return fetch(upstream.toString(), init);
}

export default {
    async fetch(request: Request, env: Env): Promise<Response> {
        const url = new URL(request.url);
        if (isBackendPath(url.pathname)) {
            return proxyToBackend(request);
        }
        return env.ASSETS.fetch(request);
    },
};
