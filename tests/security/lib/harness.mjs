/**
 * Utilidades comunes de las aceptaciones de caja negra (G1, G2): cliente HTTP con tarro de cookies,
 * registro de evidencias y alta de emisores con el comando de laboratorio (D-1).
 * Nunca escribe contraseñas ni cookies completas en la evidencia.
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

export function loadEnv(path = join(root, '.env')) {
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

export const env = { ...loadEnv(), ...process.env };

export const uniq = () => randomBytes(4).toString('hex');
export const strongPassword = () => randomBytes(18).toString('base64url');
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function requireEnv(name) {
  const v = env[name];
  if (!v) throw new Error(`Falta ${name} en .env (credenciales del seed)`);
  return v;
}

function redactCookie(c) {
  return c.replace(/^([^=]+)=([^;]*)/, (_, n, v) => `${n}=<${v.length} caracteres omitidos>`);
}

/** Cliente HTTP con su propio tarro de cookies, como un navegador independiente. */
export class Client {
  constructor(name, base) {
    this.name = name;
    this.base = base;
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
    const res = await fetch(this.base + path, {
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

/** Registro de pasos con resultado esperado y observado para la evidencia. */
export class Evidence {
  constructor(id, title, preparation, base) {
    Object.assign(this, { id, title, preparation, base, steps: [], startedAt: new Date().toISOString() });
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
      base: this.base,
      startedAt: this.startedAt,
      finishedAt: new Date().toISOString(),
      preparation: this.preparation,
      steps: this.steps,
      status: this.approved ? 'APROBADO' : 'NO APROBADO',
    };
  }
}

/**
 * Alta de emisor con el comando de laboratorio (D-1): `pnpm lab issuer:add`. La contraseña viaja por
 * variable de entorno del proceso hijo, nunca por argumento. Devuelve el id que imprime el comando.
 */
export function provisionIssuer({ email, name, password }) {
  const args = ['--silent', 'lab', 'issuer:add', '--email', email, '--name', name];
  // En Windows pnpm es un .cmd y necesita shell, que concatena sin escapar: se entrecomilla cada argumento
  // (los valores los genera la propia prueba y no contienen comillas).
  const win = process.platform === 'win32';
  const r = spawnSync(win ? `pnpm ${args.map((a) => `"${a}"`).join(' ')}` : 'pnpm', win ? [] : args, {
    cwd: root,
    env: { ...process.env, LAB_ISSUER_PASSWORD: password },
    encoding: 'utf8',
    shell: win,
  });
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`;
  const id = /\(id ([0-9a-f-]{36})\)/.exec(out)?.[1] ?? null;
  return { ok: r.status === 0 && id !== null, id, output: out.trim().split(/\r?\n/).slice(-1)[0] ?? '' };
}

/** Borrador válido con los campos de Bolivia (D-4). */
export function boliviaDraft(mensaje, overrides = {}) {
  return {
    tipo: 'GRANIZADA',
    zona: { departamento: 'LA_PAZ', municipio: 'El Alto' },
    severidad: 'NARANJA',
    mensaje,
    vigenciaHoras: 12,
    ...overrides,
  };
}

export async function assertHealthy(base) {
  const health = await fetch(base + '/health').then((r) => r.json()).catch((e) => ({ error: String(e) }));
  console.log(`API ${base} → health ${JSON.stringify(health)}`);
  if (health.status !== 'ok') throw new Error('La API no está sana; abortando sin marcar ninguna prueba.');
}
