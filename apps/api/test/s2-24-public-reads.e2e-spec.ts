import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Role } from '@alertasegura/database';
import {
  AlertaListResponseSchema,
  AlertaResponseSchema,
  ApiErrorSchema,
  TrustManifestResponseSchema,
  type SignedEnvelope,
} from '@alertasegura/shared';
import {
  API,
  createTestApp,
  createUser,
  loggedInBrowser,
  validDraftBody,
  type TestApp,
} from './support/app';
import { apiCancel, apiPublishNew, type Session } from './support/alerts';
import { expectValid, verifyWithPackage } from './support/verify';

describe('S2-24: lecturas públicas de alertas (anónimo) y sin escrituras públicas', () => {
  let t: TestApp;
  let session: Session;

  beforeAll(async () => {
    t = await createTestApp();
    session = await loggedInBrowser(t, await createUser(t.prisma, Role.ISSUER));
  });
  afterAll(async () => {
    await t.close();
  });

  it('GET /alerts sin sesión → 200, más recientes primero, con alerta, eventos y estado verificables', async () => {
    t.clock.set(new Date('2026-10-26T10:00:00Z'));
    const first = await apiPublishNew(session);
    t.clock.set(new Date('2026-10-26T10:00:05Z'));
    const second = await apiPublishNew(session, {
      ...validDraftBody,
      tipo: 'NEVADA',
      zona: { departamento: 'ORURO', municipio: null },
    });
    await apiCancel(session, first.id).expect(201);

    const anon = t.browser(); // sin cookies ni CSRF
    const res = await anon.get(`${API}/alerts?limit=100`).expect(200);
    const { alertas } = AlertaListResponseSchema.parse(res.body);
    const ids = alertas.map((a) => a.id);
    expect(ids.indexOf(second.id)).toBeLessThan(ids.indexOf(first.id));

    const listed = alertas.find((a) => a.id === first.id)!;
    expect(listed.eventos).toHaveLength(1);
    const verified = verifyWithPackage(
      [listed.alerta, listed.eventos[0], listed.estado],
      t.signer.publicJwk,
    );
    verified.forEach(expectValid);
    expect(verified[2]?.document).toMatchObject({ estado: 'CANCELADA' });
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('GET /alerts?limit= respeta el límite y valida el parámetro', async () => {
    await apiPublishNew(session);
    await apiPublishNew(session);
    const one = AlertaListResponseSchema.parse(
      (await t.browser().get(`${API}/alerts?limit=1`).expect(200)).body,
    );
    expect(one.alertas).toHaveLength(1);
    for (const bad of ['0', '101', 'abc', '-1', '1.5']) {
      await t.browser().get(`${API}/alerts?limit=${bad}`).expect(400);
    }
    const byDefault = AlertaListResponseSchema.parse(
      (await t.browser().get(`${API}/alerts`).expect(200)).body,
    );
    expect(byDefault.alertas.length).toBeLessThanOrEqual(50);
  });

  it('GET /alerts/:id sin sesión → 200 con la forma exacta del contrato; inexistente → 404; id inválido → 400', async () => {
    const alerta = await apiPublishNew(session);
    const res = await t.browser().get(`${API}/alerts/${alerta.id}`).expect(200);
    const { alerta: read } = AlertaResponseSchema.parse(res.body);
    expect(Object.keys(read).sort()).toEqual(
      [
        'alerta',
        'emisorId',
        'estado',
        'eventos',
        'id',
        'publishedAt',
        'resumen',
      ].sort(),
    );
    expect(read.alerta).toEqual(alerta.alerta);

    const missing = await t
      .browser()
      .get(`${API}/alerts/7f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f`)
      .expect(404);
    expect(ApiErrorSchema.parse(missing.body).code).toBe('NOT_FOUND');
    await t.browser().get(`${API}/alerts/no-es-uuid`).expect(400);
  });

  it('no existe ninguna escritura pública: POST/PUT/PATCH/DELETE anónimos nunca dan 2xx', async () => {
    const alerta = await apiPublishNew(session);
    const anon = t.browser();
    const attempts: Array<[string, string, number]> = [
      ['post', '/alerts', 404],
      ['put', `/alerts/${alerta.id}`, 404],
      ['patch', `/alerts/${alerta.id}`, 404],
      ['delete', `/alerts/${alerta.id}`, 404],
      ['post', `/alerts/${alerta.id}/cancel`, 401],
      ['post', `/drafts/${alerta.id}/publish`, 401],
      ['post', '/trust/manifest', 404],
      ['put', '/trust/manifest', 404],
      ['delete', '/trust/manifest', 404],
    ];
    for (const [method, route, expected] of attempts) {
      const res = await (
        anon as unknown as Record<
          string,
          (u: string) => import('supertest').Test
        >
      )
        [method](`${API}${route}`)
        .send({});
      expect({ method, route, status: res.status }).toEqual({
        method,
        route,
        status: expected,
      });
    }
    // y la alerta sigue intacta
    const read = AlertaResponseSchema.parse(
      (await anon.get(`${API}/alerts/${alerta.id}`).expect(200)).body,
    );
    expect(read.alerta.eventos).toEqual([]);
  });

  it('las lecturas públicas pasan por el rate limit global', async () => {
    const limited = await createTestApp({
      rateLimits: { global: { limit: 3, windowSeconds: 60 } },
    });
    try {
      const agent = limited.browser();
      for (let i = 0; i < 3; i += 1) {
        await agent.get(`${API}/alerts`).expect(200);
      }
      const blocked = await agent.get(`${API}/alerts`).expect(429);
      expect(blocked.body).toMatchObject({ code: 'RATE_LIMITED' });
    } finally {
      await limited.close();
    }
  });
});

describe('S2-24: GET /trust/manifest', () => {
  let dir: string;
  let file: string;
  let t: TestApp;

  const envelope = (n: number): SignedEnvelope => ({
    payload_canonico: Buffer.from(
      `{"tipo_doc":"MANIFIESTO","version":${n}}`,
    ).toString('base64url'),
    hash_payload: 'a'.repeat(64),
    firma: 'B'.repeat(86),
    key_id: 'C'.repeat(43),
  });

  beforeAll(async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'as-manifest-'));
    file = path.join(dir, 'manifest.json');
    t = await createTestApp({ trustManifestFile: file });
  });
  afterAll(async () => {
    await t.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('sin archivo → 503 con mensaje genérico (no revela rutas)', async () => {
    const res = await t.browser().get(`${API}/trust/manifest`).expect(503);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 503,
      code: 'TRUST_MANIFEST_UNAVAILABLE',
    });
    expect(JSON.stringify(res.body)).not.toContain(dir);
  });

  it('sin TRUST_MANIFEST_FILE configurado → 503', async () => {
    const unset = await createTestApp({ trustManifestFile: null });
    try {
      const res = await unset
        .browser()
        .get(`${API}/trust/manifest`)
        .expect(503);
      expect(res.body).toMatchObject({ code: 'TRUST_MANIFEST_UNAVAILABLE' });
    } finally {
      await unset.close();
    }
  });

  it('con un sobre válido → 200 tal cual lo emitió la CLI, sin sesión; un archivo nuevo se sirve sin reiniciar', async () => {
    writeFileSync(file, JSON.stringify(envelope(1)));
    const first = TrustManifestResponseSchema.parse(
      (await t.browser().get(`${API}/trust/manifest`).expect(200)).body,
    );
    expect(first.manifiesto).toEqual(envelope(1));

    writeFileSync(file, JSON.stringify(envelope(2)));
    const second = TrustManifestResponseSchema.parse(
      (await t.browser().get(`${API}/trust/manifest`).expect(200)).body,
    );
    expect(second.manifiesto).toEqual(envelope(2));
  });

  it.each([
    ['JSON inválido', 'esto no es JSON'],
    [
      'un sobre con campos de más',
      JSON.stringify({ ...envelope(1), extra: 1 }),
    ],
    [
      'un sobre al que le falta la firma',
      JSON.stringify({ ...envelope(1), firma: undefined }),
    ],
    [
      'una firma mal formada',
      JSON.stringify({ ...envelope(1), firma: 'corta' }),
    ],
  ])('%s → 503', async (_name, content) => {
    writeFileSync(file, content);
    const res = await t.browser().get(`${API}/trust/manifest`).expect(503);
    expect(res.body).toMatchObject({ code: 'TRUST_MANIFEST_UNAVAILABLE' });
  });
});
