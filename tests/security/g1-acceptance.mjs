#!/usr/bin/env node
/**
 * Aceptación GATE G1 (P01, P02a, P02b, P09) de caja negra contra la API en ejecución.
 * P13 se ejecuta aparte con las pruebas de `packages/verification` (ver run-g1.mjs).
 *
 * Requisitos: PostgreSQL arriba, migraciones y seed aplicados, API escuchando.
 * Credenciales: las del seed, leídas de `.env` (nunca se escriben en la evidencia).
 * Uso: node tests/security/g1-acceptance.mjs [--base http://localhost:3000/api/v1]
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { G1_DRAFT } from './test-data.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const env = { ...loadEnv(join(root, '.env')), ...process.env };
const argBase = process.argv.indexOf('--base');
const BASE = argBase > 0 ? process.argv[argBase + 1] : (env.G1_API_BASE ?? 'http://localhost:3000/api/v1');
const LOGIN_ACCOUNT_LIMIT = Number(env.RATE_LOGIN_ACCOUNT_LIMIT ?? 5);
const LOGIN_IP_LIMIT = Number(env.RATE_LOGIN_IP_LIMIT ?? 10);
const LOGIN_IP_TTL_S = Number(env.RATE_LOGIN_IP_WINDOW_SECONDS ?? 60);
const USER_LIMIT = Number(env.RATE_USER_LIMIT ?? 120);
const evidenceDir = join(root, 'docs', 'evidence', 'g1');

function loadEnv(path) {
  try {
    return Object.fromEntries(
      readFileSync(path, 'utf8')
        .split(/\r?\n/)
        .filter((l) => /^[A-Z0-9_]+=/.test(l))
        .map((l) => {
          const i = l.indexOf('=');
          return [l.slice(0, i), l.slice(i + 1).replace(/^"(.*)"$/, '$1')];
        }),
    );
  } catch {
    return {};
  }
}

/** Cliente HTTP con su propio tarro de cookies, como un navegador independiente. */
class Client {
  constructor(name) {
    this.name = name;
    this.cookies = new Map();
    this.csrf = null;
  }

  async request(method, path, { body, csrf = true, headers = {} } = {}) {
    const h = { accept: 'application/json', ...headers };
    if (body !== undefined) h['content-type'] = 'application/json';
    // Un token pasado explícitamente en `headers` (p. ej. el de otra sesión) no se sobrescribe.
    if (csrf && this.csrf && !['GET', 'HEAD'].includes(method) && !('x-csrf-token' in headers)) {
      h['x-csrf-token'] = this.csrf;
    }
    if (this.cookies.size) h.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(BASE + path, {
      method,
      headers: h,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const setCookie = res.headers.getSetCookie();
    for (const c of setCookie) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      if (value === '' || /max-age=0|expires=thu, 01 jan 1970/i.test(c)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { raw: text.slice(0, 200) };
    }
    return {
      status: res.status,
      json,
      retryAfter: res.headers.get('retry-after'),
      setCookie: setCookie.map(redactCookie),
    };
  }

  async fetchCsrf() {
    const r = await this.request('GET', '/auth/csrf');
    this.csrf = r.json?.csrfToken ?? null;
    return r;
  }

  async login(email, password) {
    if (!this.csrf) await this.fetchCsrf();
    const r = await this.request('POST', '/auth/login', { body: { email, password } });
    if (r.status === 200) this.csrf = r.json.csrfToken;
    return r;
  }
}

function redactCookie(c) {
  return c.replace(/^([^=]+)=([^;]*)/, (_, n, v) => `${n}=<${v.length} caracteres omitidos>`);
}

/** Registro de pasos con resultado esperado y observado para la evidencia. */
class Evidence {
  constructor(id, title, preparation) {
    Object.assign(this, { id, title, preparation, steps: [], startedAt: new Date().toISOString() });
  }

  check(step, expected, observed, ok, detail) {
    this.steps.push({ step, expected, observed, result: ok ? 'OK' : 'FALLO', ...(detail ? { detail } : {}) });
    console.log(`  ${ok ? '✔' : '✘'} [${this.id}] ${step} — esperado: ${expected}; observado: ${observed}`);
    return ok;
  }

  expectStatus(step, res, status, code) {
    const ok = res.status === status && (code === undefined || res.json?.code === code);
    return this.check(
      step,
      code ? `${status} ${code}` : String(status),
      `${res.status}${res.json?.code ? ' ' + res.json.code : ''}`,
      ok,
      { response: res.json, ...(res.retryAfter ? { retryAfter: res.retryAfter } : {}) },
    );
  }

  get approved() {
    return this.steps.length > 0 && this.steps.every((s) => s.result === 'OK');
  }

  toJSON() {
    return {
      id: this.id,
      title: this.title,
      base: BASE,
      startedAt: this.startedAt,
      finishedAt: new Date().toISOString(),
      preparation: this.preparation,
      steps: this.steps,
      status: this.approved ? 'APROBADO' : 'NO APROBADO',
    };
  }
}

const uniq = () => randomBytes(4).toString('hex');
const strongPassword = () => randomBytes(18).toString('base64url');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function requireEnv(name) {
  const v = env[name];
  if (!v) throw new Error(`Falta ${name} en .env (credenciales del seed)`);
  return v;
}

async function main() {
  mkdirSync(evidenceDir, { recursive: true });
  const health = await fetch(BASE + '/health').then((r) => r.json()).catch((e) => ({ error: String(e) }));
  console.log(`API ${BASE} → health ${JSON.stringify(health)}`);
  if (health.status !== 'ok') throw new Error('La API no está sana; abortando sin marcar ninguna prueba.');

  const adminEmail = requireEnv('SEED_ADMIN_EMAIL');
  const adminPassword = requireEnv('SEED_ADMIN_PASSWORD');
  const auditorEmail = requireEnv('SEED_AUDITOR_EMAIL');
  const auditorPassword = requireEnv('SEED_AUDITOR_PASSWORD');
  const results = [];

  // ---------- P01 ----------
  const p01 = new Evidence('P01', 'Login seguro, sesiones y roles', {
    users: ['ADMIN del seed', 'AUDITOR del seed', `emisor provisionado por ADMIN con contraseña aleatoria`],
    note: 'Las contraseñas no se registran; las cookies aparecen truncadas.',
  });
  const admin = new Client('admin');
  let r = await admin.fetchCsrf();
  p01.expectStatus('GET /auth/csrf entrega token', r, 200);
  r = await admin.login(adminEmail, 'contraseña-incorrecta-' + uniq());
  p01.expectStatus('Login ADMIN con contraseña errónea', r, 401, 'INVALID_CREDENTIALS');
  r = await admin.login(`no-existe-${uniq()}@example.test`, 'cualquier-cosa-123');
  p01.expectStatus('Login con cuenta inexistente (mismo mensaje)', r, 401, 'INVALID_CREDENTIALS');
  r = await admin.login(adminEmail, adminPassword);
  p01.expectStatus('Login ADMIN correcto', r, 200);
  const sessionCookie = r.setCookie.find((c) => /as_session=/.test(c)) ?? '';
  p01.check(
    'Cookie de sesión HttpOnly + SameSite=Strict + Path=/',
    'HttpOnly; SameSite=Strict; Path=/',
    sessionCookie || 'sin cookie',
    /httponly/i.test(sessionCookie) && /samesite=strict/i.test(sessionCookie) && /path=\//i.test(sessionCookie),
  );
  p01.check('La respuesta no expone passwordHash', 'sin passwordHash', JSON.stringify(r.json).includes('passwordHash') ? 'presente' : 'ausente', !JSON.stringify(r.json).includes('passwordHash'));
  r = await admin.request('GET', '/auth/me');
  p01.check('GET /auth/me devuelve rol ADMIN y sus permisos', '200 ADMIN [users:read, issuers:provision, audit:read]', `${r.status} ${r.json?.user?.role} [${r.json?.user?.permissions}]`, r.status === 200 && r.json.user.role === 'ADMIN' && ['users:read', 'issuers:provision', 'audit:read'].every((p) => r.json.user.permissions.includes(p)) && !r.json.user.permissions.includes('alerts:publish'));

  const issuerA = { email: `emisor-a-${uniq()}@example.test`, password: strongPassword() };
  const issuerB = { email: `emisor-b-${uniq()}@example.test`, password: strongPassword() };
  for (const [label, u] of [['A', issuerA], ['B', issuerB]]) {
    r = await admin.request('POST', '/admin/issuers', { body: { email: u.email, displayName: `Emisor ${label} G1`, password: u.password } });
    p01.check(`ADMIN provisiona emisor ${label}`, '201 role ISSUER', `${r.status} ${r.json?.user?.role}`, r.status === 201 && r.json.user.role === 'ISSUER');
    u.id = r.json?.user?.id;
  }
  r = await admin.request('POST', '/admin/issuers', { body: { email: `x-${uniq()}@example.test`, displayName: 'Con rol', password: strongPassword(), role: 'ADMIN' } });
  p01.expectStatus('Provisión con campo extra "role" se rechaza (mass assignment)', r, 400, 'VALIDATION_FAILED');

  const auditor = new Client('auditor');
  r = await auditor.login(auditorEmail, auditorPassword);
  p01.expectStatus('Login AUDITOR correcto', r, 200);
  r = await auditor.request('POST', '/admin/issuers', { body: { email: `y-${uniq()}@example.test`, displayName: 'Intruso', password: strongPassword() } });
  p01.expectStatus('AUDITOR no puede provisionar emisores', r, 403, 'FORBIDDEN');
  r = await auditor.request('GET', '/audit?limit=5');
  p01.check('AUDITOR lee la auditoría', '200 con entradas', `${r.status} ${r.json?.entries?.length ?? 0} entradas`, r.status === 200 && r.json.entries.length > 0);
  r = await auditor.request('GET', '/audit?limit=50');
  const provisioned = (r.json?.entries ?? []).filter((e) => e.action === 'ISSUER_PROVISIONED').map((e) => e.targetId);
  p01.check(
    'Alta de emisores auditada (ISSUER_PROVISIONED de A y B)',
    'ambos emisores registrados',
    [issuerA, issuerB].map((u) => (provisioned.includes(u.id) ? 'registrado' : 'ausente')).join(', '),
    provisioned.includes(issuerA.id) && provisioned.includes(issuerB.id),
  );

  const a = new Client('emisorA');
  r = await a.login(issuerA.email, issuerA.password);
  p01.expectStatus('Login emisor A correcto', r, 200);
  r = await a.request('GET', '/auth/me');
  p01.check('Emisor A tiene rol ISSUER con alerts:publish', '200 ISSUER', `${r.status} ${r.json?.user?.role}`, r.status === 200 && r.json.user.role === 'ISSUER' && r.json.user.permissions.includes('alerts:publish'));

  const stolen = new Client('cookie-copiada');
  stolen.cookies = new Map(admin.cookies);
  r = await admin.request('POST', '/auth/logout');
  p01.expectStatus('Logout ADMIN', r, 204);
  r = await stolen.request('GET', '/auth/me');
  p01.expectStatus('La cookie anterior al logout ya no vale', r, 401, 'UNAUTHENTICATED');
  r = await new Client('falsa').request('GET', '/auth/me', { headers: { cookie: `as_session=${randomBytes(32).toString('base64url')}` } });
  p01.expectStatus('Token de sesión inventado se rechaza', r, 401, 'UNAUTHENTICATED');
  results.push(p01);

  // ---------- P02a ----------
  r = await a.request('POST', '/drafts', { body: { title: G1_DRAFT.title(uniq()), body: G1_DRAFT.body, severity: 'WARNING' } });
  const draftOk = r.status === 201;
  const draftId = r.json?.draft?.id;
  const p02a = new Evidence('P02a', 'Usuario anónimo intenta publicar → 401', {
    draft: `borrador ${draftId} creado por el emisor A`,
  });
  p02a.check('Preparación: emisor A crea un borrador', '201', String(r.status), draftOk);
  const anon = new Client('anonimo');
  r = await anon.request('POST', `/drafts/${draftId}/publish`);
  p02a.expectStatus('Anónimo sin token CSRF publica', r, 401, 'UNAUTHENTICATED');
  await anon.fetchCsrf();
  r = await anon.request('POST', `/drafts/${draftId}/publish`);
  p02a.expectStatus('Anónimo con token CSRF válido publica', r, 401, 'UNAUTHENTICATED');
  r = await anon.request('GET', `/drafts/${draftId}`);
  p02a.expectStatus('Anónimo lee el borrador', r, 401, 'UNAUTHENTICATED');
  results.push(p02a);

  // ---------- P02b ----------
  const p02b = new Evidence('P02b', 'Usuario autenticado sin permisos intenta publicar → 403', {
    draft: `borrador ${draftId} del emisor A`,
    actors: ['AUDITOR (sin alerts:publish)', 'ADMIN (sin alerts:publish)', 'emisor B (no propietario)', 'emisor A (propietario)'],
  });
  r = await auditor.request('POST', `/drafts/${draftId}/publish`);
  p02b.expectStatus('AUDITOR publica', r, 403, 'FORBIDDEN');
  const admin2 = new Client('admin2');
  await admin2.login(adminEmail, adminPassword);
  r = await admin2.request('POST', `/drafts/${draftId}/publish`);
  p02b.expectStatus('ADMIN publica (separación de funciones)', r, 403, 'FORBIDDEN');
  const b = new Client('emisorB');
  r = await b.login(issuerB.email, issuerB.password);
  p02b.expectStatus('Preparación: login emisor B', r, 200);
  r = await b.request('POST', `/drafts/${draftId}/publish`);
  p02b.expectStatus('Emisor B publica borrador de A (propiedad)', r, 403, 'FORBIDDEN');
  r = await b.request('GET', `/drafts/${draftId}`);
  p02b.expectStatus('Emisor B lee borrador de A (propiedad)', r, 403, 'FORBIDDEN');
  r = await a.request('POST', `/drafts/${draftId}/publish`, { csrf: false });
  p02b.expectStatus('Emisor A publica sin X-CSRF-Token', r, 403, 'CSRF_INVALID');
  r = await a.request('POST', `/drafts/${draftId}/publish`, { headers: { 'x-csrf-token': b.csrf } });
  p02b.expectStatus('Emisor A publica con el token CSRF de otra sesión', r, 403, 'CSRF_INVALID');
  r = await a.request('POST', `/drafts/${draftId}/publish`, { headers: { origin: 'https://atacante.example' } });
  p02b.expectStatus('Emisor A publica con Origin ajeno', r, 403, 'CSRF_INVALID');
  r = await a.request('POST', `/drafts/${draftId}/publish`);
  p02b.expectStatus('Control positivo: propietario autorizado (firma pendiente S2)', r, 501, 'PUBLICATION_NOT_IMPLEMENTED');
  r = await auditor.request('GET', '/audit?limit=50');
  const actions = new Set((r.json?.entries ?? []).map((e) => e.action));
  p02b.check('Auditoría registra PUBLICATION_DENIED y PUBLICATION_AUTHORIZED', 'ambas acciones', [...actions].filter((x) => x.startsWith('PUBLICATION')).join(', ') || 'ninguna', actions.has('PUBLICATION_DENIED') && actions.has('PUBLICATION_AUTHORIZED'));
  results.push(p02b);

  // ---------- P09 ----------
  const p09 = new Evidence('P09', 'Solicitudes excesivas → 429', {
    limits: { loginPorCuenta: LOGIN_ACCOUNT_LIMIT, loginPorIp: `${LOGIN_IP_LIMIT}/${LOGIN_IP_TTL_S}s`, usuarioAutenticado: USER_LIMIT },
    note: `Se espera ${LOGIN_IP_TTL_S + 1}s para empezar con la ventana de login por IP vacía.`,
  });
  console.log(`  … esperando ${LOGIN_IP_TTL_S + 1}s para vaciar la ventana de login por IP`);
  await sleep((LOGIN_IP_TTL_S + 1) * 1000);

  const victim = `objetivo-${uniq()}@example.test`;
  const attacker = new Client('fuerza-bruta');
  await attacker.fetchCsrf();
  const statuses = [];
  for (let i = 1; i <= LOGIN_ACCOUNT_LIMIT + 1; i++) {
    r = await attacker.request('POST', '/auth/login', { body: { email: victim, password: `intento-${i}` } });
    statuses.push(r.status);
  }
  p09.check(`Login por cuenta: ${LOGIN_ACCOUNT_LIMIT} intentos 401 y el siguiente 429`, `${LOGIN_ACCOUNT_LIMIT}×401, 429`, statuses.join(','), statuses.slice(0, -1).every((s) => s === 401) && statuses.at(-1) === 429);
  p09.check('429 incluye Retry-After', 'cabecera presente', r.retryAfter ?? 'ausente', r.status === 429 && Number(r.retryAfter) > 0, { response: r.json });

  const ipStatuses = [];
  let firstIp429 = null;
  for (let i = statuses.length + 1; i <= LOGIN_IP_LIMIT + 1; i++) {
    r = await attacker.request('POST', '/auth/login', { body: { email: `rotacion-${uniq()}@example.test`, password: 'x-intento' } });
    ipStatuses.push(r.status);
    if (r.status === 429 && firstIp429 === null) firstIp429 = i;
  }
  p09.check(`Login por IP con cuentas rotadas: 429 en el intento ${LOGIN_IP_LIMIT + 1}`, `429 en ${LOGIN_IP_LIMIT + 1}`, `${ipStatuses.join(',')} (primer 429 en ${firstIp429})`, firstIp429 === LOGIN_IP_LIMIT + 1, { response: r.json, retryAfter: r.retryAfter });

  const userStatuses = new Map();
  let firstUser429 = null;
  for (let i = 1; i <= USER_LIMIT + 1; i++) {
    r = await a.request('GET', '/drafts');
    userStatuses.set(r.status, (userStatuses.get(r.status) ?? 0) + 1);
    if (r.status === 429 && firstUser429 === null) firstUser429 = i;
  }
  p09.check(`Usuario autenticado: 429 tras ${USER_LIMIT} peticiones`, `429 en la petición ≤ ${USER_LIMIT + 1}`, `${JSON.stringify(Object.fromEntries(userStatuses))} (primer 429 en ${firstUser429})`, firstUser429 !== null && firstUser429 <= USER_LIMIT + 1, { response: r.json, retryAfter: r.retryAfter });
  r = await b.request('GET', '/drafts');
  p09.expectStatus('Otro usuario no queda bloqueado por el límite del emisor A', r, 200);
  r = await auditor.request('GET', '/audit?limit=100');
  p09.check('Auditoría registra RATE_LIMITED', 'presente', (r.json?.entries ?? []).some((e) => e.action === 'RATE_LIMITED') ? 'presente' : `ausente (${r.status})`, (r.json?.entries ?? []).some((e) => e.action === 'RATE_LIMITED'));
  results.push(p09);

  for (const ev of results) writeFileSync(join(evidenceDir, `${ev.id}.json`), JSON.stringify(ev, null, 2) + '\n');
  console.log('\nResumen:');
  for (const ev of results) console.log(`  ${ev.id}: ${ev.approved ? 'APROBADO' : 'NO APROBADO'}`);
  process.exitCode = results.every((e) => e.approved) ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 2;
});
