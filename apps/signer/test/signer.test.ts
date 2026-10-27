import { generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { mkdtempSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { request, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SignResponseSchema, SignerErrorSchema, SignerHealthSchema } from '@alertasegura/shared';
import { computeKid, verifyDocument, VerificationError } from '@alertasegura/verification';
import { loadSigningKey } from '../src/key.ts';
import { createSignerServer, listenOnSocket, type SignerLogger } from '../src/server.ts';

const UUID_A = '3f1c9a52-8d3e-4c1b-9f6a-2b7d5e1a0c11';
const UUID_B = '9b2e7f10-4a6d-4d58-8c33-5e0f1a7b2d44';
const UUID_C = 'c4d8a1e6-7b52-4f09-a1d3-6e8b9c0f2a77';
const MENSAJE_SECRETO = 'Mensaje de prueba que nunca debe aparecer en los registros.';

const alerta = () => ({
  tipo_doc: 'ALERTA',
  version: 1,
  alerta_id: UUID_A,
  emisor_id: UUID_B,
  tipo: 'INUNDACION',
  zona: { departamento: 'SANTA_CRUZ', municipio: 'Warnes' },
  severidad: 'NARANJA',
  mensaje: MENSAJE_SECRETO,
  emitida_en: '2026-10-26T14:05:09Z',
  expira_en: '2026-10-26T20:05:09Z',
});
const evento = () => ({
  tipo_doc: 'EVENTO',
  version: 1,
  evento_id: UUID_C,
  alerta_id: UUID_A,
  hash_alerta: 'a'.repeat(64),
  emisor_id: UUID_B,
  accion: 'CANCELACION',
  emitida_en: '2026-10-26T15:00:00Z',
});
const estado = () => ({
  tipo_doc: 'ESTADO',
  version: 1,
  alerta_id: UUID_A,
  secuencia: 0,
  ultimo_evento_hash: null,
  estado: 'VIGENTE',
  issued_at: '2026-10-26T14:05:10Z',
  expires_at: '2026-10-26T14:15:10Z',
});

interface Reply {
  status: number;
  body: unknown;
  raw: string;
}

function call(socketPath: string, method: string, path: string, body?: string | Buffer): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath, method, path, headers: body === undefined ? {} : { 'content-type': 'application/json' } }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        let parsed: unknown = null;
        try {
          parsed = JSON.parse(raw);
        } catch {
          // cuerpo no JSON
        }
        resolve({ status: res.statusCode ?? 0, body: parsed, raw });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const sign = (socketPath: string, doc: unknown) => call(socketPath, 'POST', '/sign', JSON.stringify(doc));

let tmp: string;
let socketPath: string;
let server: Server;
let logs: string[];
let privateKey: KeyObject;
let jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
let keyId: string;

const logger: SignerLogger = {
  info: (event, fields) => logs.push(JSON.stringify({ event, ...fields })),
  error: (event, fields) => logs.push(JSON.stringify({ event, ...fields })),
};

async function start(keyPath: string | undefined): Promise<void> {
  server = createSignerServer({ key: await loadSigningKey(keyPath), logger });
  await listenOnSocket(server, socketPath);
}

beforeEach(async () => {
  tmp = mkdtempSync(join(tmpdir(), 'signer-'));
  socketPath = process.platform === 'win32' ? `\\\\.\\pipe\\as-signer-${randomBytes(6).toString('hex')}` : join(tmp, 'signer.sock');
  logs = [];
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  privateKey = pair.privateKey;
  const { kty, crv, x, y } = pair.publicKey.export({ format: 'jwk' });
  jwk = { kty: kty as 'EC', crv: crv as 'P-256', x: x!, y: y! };
  keyId = await computeKid(jwk);
});

afterEach(async () => {
  await new Promise<void>((resolve) => {
    if (server?.listening) server.close(() => resolve());
    else resolve();
  });
  rmSync(tmp, { recursive: true, force: true });
});

function writeKey(name = 'signer.pem'): string {
  const path = join(tmp, name);
  writeFileSync(path, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o400 });
  return path;
}

describe('POST /sign con la clave disponible', () => {
  beforeEach(async () => {
    await start(writeKey());
  });

  it('firma ALERTA, EVENTO y ESTADO y el resultado verifica con verifyDocument', async () => {
    for (const [doc, tipo] of [
      [alerta(), 'ALERTA'],
      [evento(), 'EVENTO'],
      [estado(), 'ESTADO'],
    ] as const) {
      const reply = await sign(socketPath, doc);
      expect(reply.status).toBe(200);
      const envelope = SignResponseSchema.parse(reply.body);
      expect(envelope.key_id).toBe(keyId);
      const verified = await verifyDocument({ envelope, jwk, tipoEsperado: tipo });
      expect(verified).toMatchObject({ ...doc, key_id: keyId });
    }
  });

  it('el payload firmado incluye el key_id añadido por el firmante', async () => {
    const reply = await sign(socketPath, alerta());
    const payload = JSON.parse(Buffer.from((reply.body as { payload_canonico: string }).payload_canonico, 'base64url').toString('utf8'));
    expect(payload.key_id).toBe(keyId);
  });

  it('un tipo cambiado no verifica como otro tipo (P16)', async () => {
    const reply = await sign(socketPath, evento());
    const envelope = SignResponseSchema.parse(reply.body);
    await expect(verifyDocument({ envelope, jwk, tipoEsperado: 'ALERTA' })).rejects.toBeInstanceOf(VerificationError);
  });

  it('rechaza un campo extra con 400', async () => {
    const reply = await sign(socketPath, { ...alerta(), extra: 1 });
    expect(reply.status).toBe(400);
    expect(SignerErrorSchema.parse(reply.body).code).toBe('INVALID_DOCUMENT');
  });

  it('rechaza que el cliente envíe su propio key_id', async () => {
    const reply = await sign(socketPath, { ...alerta(), key_id: 'A'.repeat(43) });
    expect(reply.status).toBe(400);
  });

  it('rechaza MANIFIESTO y tipo_doc desconocido', async () => {
    expect((await sign(socketPath, { tipo_doc: 'MANIFIESTO', version: 1 })).status).toBe(400);
    expect((await sign(socketPath, { ...alerta(), tipo_doc: 'OTRO' })).status).toBe(400);
    expect((await sign(socketPath, [])).status).toBe(400);
    expect((await sign(socketPath, null)).status).toBe(400);
  });

  it('rechaza fechas con milisegundos, sin zona o inexistentes', async () => {
    expect((await sign(socketPath, { ...alerta(), emitida_en: '2026-10-26T14:05:09.123Z' })).status).toBe(400);
    expect((await sign(socketPath, { ...alerta(), emitida_en: '2026-10-26T14:05:09-04:00' })).status).toBe(400);
    expect((await sign(socketPath, { ...alerta(), emitida_en: '2026-02-30T14:05:09Z' })).status).toBe(400);
    expect((await sign(socketPath, { ...alerta(), emitida_en: '2026-13-01T25:61:61Z' })).status).toBe(400);
  });

  it('rechaza una alerta que expira antes de emitirse y un ESTADO que dura más de 10 minutos', async () => {
    expect((await sign(socketPath, { ...alerta(), expira_en: '2026-10-26T14:05:09Z' })).status).toBe(400);
    expect((await sign(socketPath, { ...estado(), expires_at: '2026-10-26T14:15:11Z' })).status).toBe(400);
    expect((await sign(socketPath, { ...estado(), expires_at: '2026-10-26T14:05:10Z' })).status).toBe(400);
    expect((await sign(socketPath, { ...estado(), expires_at: '2026-10-26T14:15:10Z' })).status).toBe(200);
  });

  it('rechaza JSON inválido y cuerpo vacío', async () => {
    expect((await call(socketPath, 'POST', '/sign', '{"tipo_doc":')).status).toBe(400);
    expect((await call(socketPath, 'POST', '/sign', '')).status).toBe(400);
  });

  it('rechaza cuerpos de más de 16 kB', async () => {
    const big = JSON.stringify({ ...alerta(), mensaje: 'x'.repeat(17 * 1024) });
    const reply = await call(socketPath, 'POST', '/sign', big);
    expect(reply.status).toBe(413);
    // El servicio sigue sano después.
    expect((await sign(socketPath, alerta())).status).toBe(200);
  });

  it('un mensaje de 1000 caracteres multibyte cabe dentro del límite de 16 kB', async () => {
    const ok = await sign(socketPath, { ...alerta(), mensaje: 'ñ'.repeat(1000) });
    expect(ok.status).toBe(200);
  });

  it('responde 404 en rutas desconocidas y 405 en métodos incorrectos', async () => {
    expect((await call(socketPath, 'GET', '/otra')).status).toBe(404);
    expect((await call(socketPath, 'GET', '/sign')).status).toBe(405);
    expect((await call(socketPath, 'POST', '/health', '{}')).status).toBe(405);
  });

  it('no registra el payload ni la clave', async () => {
    await sign(socketPath, alerta());
    await sign(socketPath, { ...alerta(), extra: 1 });
    const text = logs.join('\n');
    expect(text).toContain('signed');
    expect(text).not.toContain(MENSAJE_SECRETO);
    expect(text).not.toContain(UUID_A);
    expect(text).not.toMatch(/PRIVATE KEY/);
  });

  it('los errores no devuelven valores del cuerpo ni rutas de archivos', async () => {
    const reply = await sign(socketPath, { ...alerta(), mensaje: 'corto' });
    expect(reply.status).toBe(400);
    expect(reply.raw).not.toContain('corto');
    expect(reply.raw).toContain('mensaje');
  });
});

describe('GET /health', () => {
  it('informa el key_id activo y nunca la clave privada', async () => {
    await start(writeKey());
    const reply = await call(socketPath, 'GET', '/health');
    expect(reply.status).toBe(200);
    expect(SignerHealthSchema.parse(reply.body)).toEqual({ status: 'ok', key_id: keyId });
    expect(reply.raw).not.toMatch(/"d"\s*:|PRIVATE/);
  });
});

describe('clave', () => {
  it('se lee una sola vez: borrar el archivo después de arrancar no afecta a la firma', async () => {
    const keyPath = writeKey();
    await start(keyPath);
    unlinkSync(keyPath);
    expect((await sign(socketPath, alerta())).status).toBe(200);
  });

  it('clave ausente → 503 KEY_UNAVAILABLE en /sign y /health', async () => {
    await start(join(tmp, 'no-existe.pem'));
    const reply = await sign(socketPath, alerta());
    expect(reply.status).toBe(503);
    expect(SignerErrorSchema.parse(reply.body).code).toBe('KEY_UNAVAILABLE');
    expect(reply.raw).not.toContain(tmp);
    expect((await call(socketPath, 'GET', '/health')).status).toBe(503);
  });

  it('sin SIGNER_PRIVATE_KEY_PATH → 503', async () => {
    await start(undefined);
    expect((await sign(socketPath, alerta())).status).toBe(503);
  });

  it('un archivo que no es una clave P-256 → 503', async () => {
    const path = join(tmp, 'basura.pem');
    writeFileSync(path, 'no es una clave');
    await start(path);
    expect((await sign(socketPath, alerta())).status).toBe(503);
  });

  it('una clave RSA o de otra curva → 503', async () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-384' }).privateKey;
    const path = join(tmp, 'p384.pem');
    writeFileSync(path, other.export({ type: 'pkcs8', format: 'pem' }));
    await start(path);
    expect((await sign(socketPath, alerta())).status).toBe(503);
  });
});

describe('socket', () => {
  it.skipIf(process.platform === 'win32')('se crea con permisos 0660', async () => {
    await start(writeKey());
    expect(statSync(socketPath).mode & 0o777).toBe(0o660);
  });

  it.skipIf(process.platform === 'win32')('reutiliza la ruta si quedó un socket huérfano, sin borrar archivos normales', async () => {
    await start(writeKey());
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await start(writeKey('segunda.pem'));
    expect((await call(socketPath, 'GET', '/health')).status).toBe(200);
  });
});
