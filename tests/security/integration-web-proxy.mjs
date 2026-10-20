#!/usr/bin/env node
/**
 * Integración PWA ⇄ API a través del proxy de Vite (http://localhost:5173/api → :3000),
 * reproduciendo lo que hace el navegador: mismo origen, cabecera Origin y cookies.
 * Requiere `pnpm dev:web` y la API en marcha. Usa el emisor 1 del seed (.env).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const env = Object.fromEntries(
  readFileSync(join(root, '.env'), 'utf8')
    .split(/\r?\n/)
    .filter((l) => /^[A-Z0-9_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);
const WEB = 'http://localhost:5173';
const cookies = new Map();
let csrf = null;
const steps = [];

async function call(method, path, body) {
  const headers = { accept: 'application/json', origin: WEB };
  if (body) headers['content-type'] = 'application/json';
  if (csrf && method !== 'GET') headers['x-csrf-token'] = csrf;
  if (cookies.size) headers.cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  const res = await fetch(WEB + '/api/v1' + path, { method, headers, body: body && JSON.stringify(body) });
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(';');
    const [k, v] = [pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1)];
    if (v) cookies.set(k, v);
    else cookies.delete(k);
  }
  const json = res.status === 204 ? null : await res.json().catch(() => null);
  return { status: res.status, json, retryAfter: res.headers.get('retry-after') };
}

function check(step, ok, observed) {
  steps.push({ step, result: ok ? 'OK' : 'FALLO', observed });
  console.log(`  ${ok ? '✔' : '✘'} ${step} — ${observed}`);
}

const index = await fetch(WEB + '/').then((r) => r.text());
check('Vite sirve la PWA', index.includes('<div id="root">'), 'index.html con #root');
let r = await call('GET', '/health');
check('GET /api/v1/health vía proxy', r.status === 200 && r.json?.database === 'up', `${r.status} ${JSON.stringify(r.json)}`);
r = await call('GET', '/auth/csrf');
csrf = r.json?.csrfToken;
check('GET /auth/csrf vía proxy fija cookie as_csrf', r.status === 200 && cookies.has('as_csrf'), `${r.status}`);
const credentials = { email: env.SEED_ISSUER1_EMAIL, password: env.SEED_ISSUER1_PASSWORD };
r = await call('POST', '/auth/login', credentials);
if (r.status === 429) {
  // Si se ejecuta justo después de g1-acceptance (P09 agota el login por IP), se respeta Retry-After.
  const wait = Number(r.retryAfter ?? 61);
  check(`Login limitado por P09 previo: se respeta Retry-After (${wait}s)`, wait > 0 && wait <= 120, `429, Retry-After ${wait}`);
  await new Promise((done) => setTimeout(done, (wait + 1) * 1000));
  r = await call('POST', '/auth/login', credentials);
}
if (r.status === 200) csrf = r.json.csrfToken;
check('Login emisor 1 con Origin http://localhost:5173', r.status === 200 && cookies.has('as_session'), `${r.status} ${r.json?.user?.role ?? r.json?.code}`);
r = await call('GET', '/auth/me');
check('GET /auth/me con la cookie de sesión', r.status === 200 && r.json?.user?.role === 'ISSUER', `${r.status} ${r.json?.user?.email}`);
r = await call('GET', '/drafts');
check('GET /drafts (borradores del seed)', r.status === 200 && Array.isArray(r.json?.drafts), `${r.status} ${r.json?.drafts?.length} borradores`);
r = await call('POST', '/auth/logout');
check('Logout', r.status === 204, String(r.status));
r = await call('GET', '/auth/me');
check('Tras logout /auth/me → 401', r.status === 401, `${r.status} ${r.json?.code}`);

const ok = steps.every((s) => s.result === 'OK');
writeFileSync(
  join(root, 'docs', 'evidence', 'g1', 'integracion-web-api.json'),
  JSON.stringify({ at: new Date().toISOString(), via: WEB, steps, status: ok ? 'APROBADO' : 'NO APROBADO' }, null, 2) + '\n',
);
console.log(ok ? 'Integración: APROBADO' : 'Integración: NO APROBADO');
process.exitCode = ok ? 0 : 1;
