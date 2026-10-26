import { createHash, randomBytes } from 'node:crypto';
import { Role } from '@alertasegura/database';
import {
  AlertaResponseSchema,
  CSRF_HEADER,
  DraftResponseSchema,
} from '@alertasegura/shared';
import { SessionPurgeService } from '../src/modules/auth/session-purge.service';
import {
  API,
  createTestApp,
  createUser,
  loggedInBrowser,
  validDraftBody,
  type TestApp,
} from './support/app';

const HOUR = 3600_000;

describe('S2-48: purga de sesiones caducadas', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });

  /** Fila de sesión escrita con el propietario, con las fechas que se indiquen. */
  const makeSession = async (
    userId: string,
    when: { expiresAt?: Date; lastSeenAt?: Date; revokedAt?: Date | null },
  ) =>
    t.owner.session.create({
      data: {
        userId,
        tokenHash: createHash('sha256').update(randomBytes(32)).digest('hex'),
        expiresAt: when.expiresAt ?? new Date(Date.now() + 8 * HOUR),
        lastSeenAt: when.lastSeenAt ?? new Date(),
        revokedAt: when.revokedAt ?? null,
      },
    });

  it('borra las caducadas, las inactivas y las revocadas hace más de 24 h; conserva las demás', async () => {
    const user = await createUser(t.prisma, Role.ISSUER);
    const keep = {
      active: await makeSession(user.id, {}),
      recentlyRevoked: await makeSession(user.id, {
        revokedAt: new Date(Date.now() - HOUR),
      }),
    };
    const drop = {
      expired: await makeSession(user.id, {
        expiresAt: new Date(Date.now() - 1000),
      }),
      idle: await makeSession(user.id, {
        lastSeenAt: new Date(Date.now() - 31 * 60_000), // más de 30 min sin actividad
      }),
      oldRevoked: await makeSession(user.id, {
        revokedAt: new Date(Date.now() - 25 * HOUR),
      }),
    };

    const purged = await t.app.get(SessionPurgeService).purgeExpired();
    expect(purged).toBeGreaterThanOrEqual(3);

    const remaining = new Set(
      (await t.owner.session.findMany({ where: { userId: user.id } })).map(
        (s) => s.id,
      ),
    );
    for (const s of Object.values(keep)) expect(remaining.has(s.id)).toBe(true);
    for (const s of Object.values(drop))
      expect(remaining.has(s.id)).toBe(false);
  });

  it('una sesión viva sobrevive a la purga y sigue autenticando; una caducada ya no autentica', async () => {
    const user = await createUser(t.prisma, Role.ISSUER);
    const { agent } = await loggedInBrowser(t, user);
    await agent.get(`${API}/auth/me`).expect(200);

    await t.app.get(SessionPurgeService).purgeExpired();
    await agent.get(`${API}/auth/me`).expect(200); // la purga no la tocó

    await t.owner.session.updateMany({
      where: { userId: user.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect(
      await t.app.get(SessionPurgeService).purgeExpired(),
    ).toBeGreaterThanOrEqual(1);
    expect(await t.owner.session.count({ where: { userId: user.id } })).toBe(0);
    await agent.get(`${API}/auth/me`).expect(401);
  });

  it('también purga al arrancar la API, y lo hace con el rol de la app (DELETE solo en Session)', async () => {
    const user = await createUser(t.prisma, Role.ISSUER);
    const stale = await makeSession(user.id, {
      expiresAt: new Date(Date.now() - HOUR),
    });
    const booted = await createTestApp(); // arranque nuevo = purga inicial
    try {
      expect(
        await t.owner.session.findUnique({ where: { id: stale.id } }),
      ).toBeNull();
    } finally {
      await booted.close();
    }
  });
});

describe('S2-48: cabeceras de seguridad y CSP de la API', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });

  const EXPECTED_CSP =
    "default-src 'none';frame-ancestors 'none';base-uri 'none';form-action 'none'";

  it.each([
    ['una respuesta 200', '/health', 200],
    ['una lectura pública', '/alerts', 200],
    ['un 404', '/no-existe', 404],
    ['un 401', '/auth/me', 401],
  ])(
    '%s lleva la CSP estricta y el resto de cabeceras',
    async (_name, route, status) => {
      const res = await t.browser().get(`${API}${route}`).expect(status);
      expect(res.headers['content-security-policy']).toBe(EXPECTED_CSP);
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['cross-origin-resource-policy']).toBe('same-origin');
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(res.headers['strict-transport-security']).toBeDefined();
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['x-powered-by']).toBeUndefined();
    },
  );
});

describe('S2-45: API detrás de la PWA con TLS de laboratorio (WEB_ORIGIN https, COOKIE_SECURE=true)', () => {
  const HTTPS_ORIGIN = 'https://localhost:5173';
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp({ cookieSecure: true, webOrigin: HTTPS_ORIGIN });
  });
  afterAll(async () => {
    await t.close();
  });

  it('login, borrador y publicación con cookies __Host- y Origin https; el Origin http se rechaza (CSRF_INVALID)', async () => {
    const user = await createUser(t.prisma, Role.ISSUER);
    // El agente de pruebas habla HTTP y no reenvía cookies Secure: se envían a mano, como haría el navegador por HTTPS.
    const agent = t.browser();
    const pre = await agent.get(`${API}/auth/csrf`).expect(200);
    const preToken = (pre.body as { csrfToken: string }).csrfToken;

    const login = await agent
      .post(`${API}/auth/login`)
      .set('Origin', HTTPS_ORIGIN)
      .set('Cookie', `__Host-as_csrf=${preToken}`)
      .set(CSRF_HEADER, preToken)
      .send({ email: user.email, password: user.password })
      .expect(200);
    const cookies = login.headers['set-cookie'] as unknown as string[];
    const sessionCookie = cookies.find((c) =>
      c.startsWith('__Host-as_session='),
    );
    const csrfCookie = cookies.find((c) => c.startsWith('__Host-as_csrf='));
    expect(sessionCookie).toMatch(/;\s*Secure/i);
    expect(csrfCookie).toMatch(/;\s*Secure/i);
    const cookieHeader = [sessionCookie, csrfCookie]
      .map((c) => (c ?? '').split(';')[0])
      .join('; ');
    const csrf = (login.body as { csrfToken: string }).csrfToken;

    const post = (path: string, body?: object) =>
      agent
        .post(`${API}${path}`)
        .set('Cookie', cookieHeader)
        .set(CSRF_HEADER, csrf)
        .send(body ?? {});

    const draft = await post('/drafts', validDraftBody)
      .set('Origin', HTTPS_ORIGIN)
      .expect(201);
    const draftId = DraftResponseSchema.parse(draft.body).draft.id;

    // El mismo navegador pero desde el origen http de la semana 1 ya no es el origen de la PWA
    const wrongOrigin = await post(`/drafts/${draftId}/publish`)
      .set('Origin', 'http://localhost:5173')
      .expect(403);
    expect(wrongOrigin.body).toMatchObject({ code: 'CSRF_INVALID' });

    const published = await post(`/drafts/${draftId}/publish`)
      .set('Origin', HTTPS_ORIGIN)
      .expect(201);
    AlertaResponseSchema.parse(published.body);
  });
});
