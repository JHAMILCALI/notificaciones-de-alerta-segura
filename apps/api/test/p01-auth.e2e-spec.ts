import { Role } from '@alertasegura/database';
import {
  ApiErrorSchema,
  CSRF_HEADER,
  CsrfResponseSchema,
  LoginResponseSchema,
  MeResponseSchema,
  ROLE_PERMISSIONS,
} from '@alertasegura/shared';
import {
  API,
  WEB_ORIGIN,
  auditRows,
  createTestApp,
  createUser,
  fetchCsrf,
  login,
  type TestApp,
  type TestUser,
} from './support/app';

function cookieNamed(
  setCookie: string[] | undefined,
  name: string,
): string | undefined {
  return setCookie?.find((c) => c.startsWith(`${name}=`));
}

function cookieValue(setCookie: string[], name: string): string {
  const raw = cookieNamed(setCookie, name);
  if (!raw) throw new Error(`cookie ${name} ausente`);
  return decodeURIComponent(raw.split(';')[0].slice(name.length + 1));
}

describe('P01: autenticación y ciclo de la sesión', () => {
  let t: TestApp;
  let issuer: TestUser;

  beforeAll(async () => {
    t = await createTestApp();
    issuer = await createUser(t.prisma, Role.ISSUER);
  });
  afterAll(async () => {
    await t.close();
  });

  describe('login correcto', () => {
    it('responde 200 con usuario, rol y permisos (contrato LoginResponse)', async () => {
      const agent = t.browser();
      const pre = await fetchCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, pre)
        .send({ email: issuer.email.toUpperCase(), password: issuer.password }) // se normaliza
        .expect(200);
      const body = LoginResponseSchema.parse(res.body);
      expect(body.user.id).toBe(issuer.id);
      expect(body.user.role).toBe('ISSUER');
      expect(body.user.permissions).toEqual([...ROLE_PERMISSIONS.ISSUER]);
      expect(body.csrfToken).not.toBe(pre); // el token CSRF rota con la sesión
      expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|argon2/i);
    });

    it('la cookie de sesión es HttpOnly y SameSite=Strict, con Path=/ y sin Secure en HTTP local', async () => {
      const agent = t.browser();
      const { setCookie } = await login(agent, issuer);
      const session = cookieNamed(setCookie, 'as_session');
      const csrf = cookieNamed(setCookie, 'as_csrf');
      expect(session).toBeDefined();
      expect(session).toMatch(/;\s*HttpOnly/i);
      expect(session).toMatch(/;\s*SameSite=Strict/i);
      expect(session).toMatch(/;\s*Path=\//i);
      expect(session).not.toMatch(/;\s*Secure/i);
      expect(session).not.toMatch(/Domain=/i);
      expect(session).toMatch(/Max-Age=28800|Expires=/i);
      expect(csrf).toMatch(/;\s*HttpOnly/i);
      expect(csrf).toMatch(/;\s*SameSite=Strict/i);
    });

    it('GET /auth/me devuelve identidad, rol y permisos', async () => {
      const agent = t.browser();
      await login(agent, issuer);
      const res = await agent.get(`${API}/auth/me`).expect(200);
      const { user } = MeResponseSchema.parse(res.body);
      expect(user).toMatchObject({
        id: issuer.id,
        email: issuer.email,
        role: 'ISSUER',
      });
      expect(user.permissions).toEqual([...ROLE_PERMISSIONS.ISSUER]);
    });

    it('devuelve rol y permisos correctos para ADMIN y AUDITOR', async () => {
      for (const role of [Role.ADMIN, Role.AUDITOR] as const) {
        const u = await createUser(t.prisma, role);
        const agent = t.browser();
        await login(agent, u);
        const res = await agent.get(`${API}/auth/me`).expect(200);
        const { user } = MeResponseSchema.parse(res.body);
        expect(user.role).toBe(role);
        expect(user.permissions).toEqual([...ROLE_PERMISSIONS[role]]);
      }
    });

    it('la contraseña se guarda con Argon2id y en BD solo está el SHA-256 del token de sesión', async () => {
      const agent = t.browser();
      const { setCookie } = await login(agent, issuer);
      const stored = await t.prisma.user.findUniqueOrThrow({
        where: { id: issuer.id },
      });
      expect(stored.passwordHash.startsWith('$argon2id$')).toBe(true);
      expect(stored.passwordHash).not.toContain(issuer.password);

      const token = cookieValue(setCookie, 'as_session');
      expect(token).toHaveLength(43); // 32 bytes en base64url
      const sessions = await t.prisma.session.findMany({
        where: { userId: issuer.id },
      });
      expect(sessions.length).toBeGreaterThan(0);
      for (const s of sessions) {
        expect(s.tokenHash).toMatch(/^[0-9a-f]{64}$/);
        expect(s.tokenHash).not.toBe(token);
        expect(JSON.stringify(s)).not.toContain(token);
      }
    });

    it('audita AUTH_LOGIN_SUCCEEDED sin credenciales ni tokens', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      const { setCookie, csrfToken } = await login(agent, u);
      const rows = await auditRows(t.prisma, {
        actorId: u.id,
        action: 'AUTH_LOGIN_SUCCEEDED',
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        outcome: 'SUCCESS',
        targetType: 'session',
      });
      const dump = JSON.stringify(rows);
      expect(dump).not.toContain(u.password);
      expect(dump).not.toContain(csrfToken);
      expect(dump).not.toContain(cookieValue(setCookie, 'as_session'));
    });
  });

  describe('login incorrecto', () => {
    it('contraseña errónea → 401 INVALID_CREDENTIALS genérico', async () => {
      const agent = t.browser();
      const pre = await fetchCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, pre)
        .send({ email: issuer.email, password: 'contraseña-incorrecta' })
        .expect(401);
      const err = ApiErrorSchema.parse(res.body);
      expect(err.code).toBe('INVALID_CREDENTIALS');
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('correo inexistente, contraseña errónea y cuenta DISABLED devuelven el mismo cuerpo', async () => {
      const disabled = await createUser(t.prisma, Role.ISSUER, {
        status: 'DISABLED',
      });
      const agent = t.browser();
      const pre = await fetchCsrf(agent);
      const attempt = (email: string, password: string) =>
        agent
          .post(`${API}/auth/login`)
          .set(CSRF_HEADER, pre)
          .send({ email, password });

      const wrongPassword = await attempt(issuer.email, 'mala-contraseña-1');
      const unknown = await attempt(
        'nadie-existe@test.local',
        'mala-contraseña-1',
      );
      const disabledRes = await attempt(disabled.email, disabled.password); // credenciales correctas

      for (const res of [wrongPassword, unknown, disabledRes]) {
        expect(res.status).toBe(401);
        expect(res.body).toEqual({
          statusCode: 401,
          code: 'INVALID_CREDENTIALS',
          message: 'Credenciales inválidas',
        });
      }
    });

    it('audita AUTH_LOGIN_FAILED con el motivo interno pero nunca la contraseña', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      const pre = await fetchCsrf(agent);
      const attempted = 'intento-fallido-Zz9!';
      await agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, pre)
        .send({ email: u.email, password: attempted })
        .expect(401);
      const rows = await auditRows(t.prisma, {
        actorId: u.id,
        action: 'AUTH_LOGIN_FAILED',
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ outcome: 'FAILURE' });
      expect(rows[0]?.metadata).toMatchObject({
        email: u.email,
        reason: 'bad_password',
      });
      expect(JSON.stringify(rows)).not.toContain(attempted);
    });

    it('el login exige token CSRF: sin él → 403 CSRF_INVALID', async () => {
      const agent = t.browser();
      const res = await agent
        .post(`${API}/auth/login`)
        .send({ email: issuer.email, password: issuer.password })
        .expect(403);
      expect(res.body).toMatchObject({ code: 'CSRF_INVALID' });
    });

    it('un Origin distinto de WEB_ORIGIN se rechaza aunque el token sea válido', async () => {
      const agent = t.browser();
      const pre = await fetchCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login`)
        .set('Origin', 'https://evil.example')
        .set(CSRF_HEADER, pre)
        .send({ email: issuer.email, password: issuer.password })
        .expect(403);
      expect(res.body).toMatchObject({ code: 'CSRF_INVALID' });
      await agent
        .post(`${API}/auth/login`)
        .set('Origin', WEB_ORIGIN)
        .set(CSRF_HEADER, pre)
        .send({ email: issuer.email, password: issuer.password })
        .expect(200);
    });
  });

  describe('logout', () => {
    it('revoca la sesión: la cookie anterior deja de valer (401) aunque se reenvíe a mano', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      const { csrfToken, setCookie } = await login(agent, u);
      const oldSession = cookieValue(setCookie, 'as_session');
      await agent.get(`${API}/auth/me`).expect(200);

      const out = await agent
        .post(`${API}/auth/logout`)
        .set(CSRF_HEADER, csrfToken)
        .expect(204);
      // el servidor ordena borrar las cookies
      expect(
        cookieNamed(
          out.headers['set-cookie'] as unknown as string[],
          'as_session',
        ),
      ).toMatch(/Expires=Thu, 01 Jan 1970/i);

      await agent.get(`${API}/auth/me`).expect(401);

      // Un atacante que hubiera copiado la cookie tampoco puede reutilizarla.
      const replay = await t
        .browser()
        .get(`${API}/auth/me`)
        .set('Cookie', `as_session=${oldSession}`)
        .expect(401);
      expect(ApiErrorSchema.parse(replay.body).code).toBe('UNAUTHENTICATED');

      const row = await t.prisma.session.findMany({ where: { userId: u.id } });
      expect(row).toHaveLength(1);
      expect(row[0]?.revokedAt).not.toBeNull();
      const audit = await auditRows(t.prisma, {
        actorId: u.id,
        action: 'AUTH_LOGOUT',
      });
      expect(audit).toHaveLength(1);
    });

    it('exige CSRF: sin token la sesión sigue viva', async () => {
      const agent = t.browser();
      await login(agent, issuer);
      const res = await agent.post(`${API}/auth/logout`).expect(403);
      expect(res.body).toMatchObject({ code: 'CSRF_INVALID' });
      await agent.get(`${API}/auth/me`).expect(200);
    });

    it('anónimo → 401', async () => {
      await t.browser().post(`${API}/auth/logout`).expect(401);
    });

    it('tras el logout el token CSRF anterior ya no sirve (hay que pedir otro)', async () => {
      const agent = t.browser();
      const { csrfToken } = await login(agent, issuer);
      await agent
        .post(`${API}/auth/logout`)
        .set(CSRF_HEADER, csrfToken)
        .expect(204);
      const fresh = CsrfResponseSchema.parse(
        (await agent.get(`${API}/auth/csrf`).expect(200)).body,
      );
      expect(fresh.csrfToken).not.toBe(csrfToken);
      // el viejo (ligado a la sesión revocada) no vale como token anónimo
      await agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, csrfToken)
        .send({ email: issuer.email, password: issuer.password })
        .expect(403);
      await agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, fresh.csrfToken)
        .send({ email: issuer.email, password: issuer.password })
        .expect(200);
    });
  });

  describe('rotación de sesión', () => {
    it('un nuevo login revoca la sesión previa del navegador y emite un token distinto', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      const first = await login(agent, u);
      const firstToken = cookieValue(first.setCookie, 'as_session');

      // segundo login desde el mismo navegador (con la sesión 1 todavía viva)
      const res = await agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, first.csrfToken)
        .send({ email: u.email, password: u.password })
        .expect(200);
      const secondToken = cookieValue(
        res.headers['set-cookie'] as unknown as string[],
        'as_session',
      );
      expect(secondToken).not.toBe(firstToken);

      // la sesión anterior ya no sirve
      await t
        .browser()
        .get(`${API}/auth/me`)
        .set('Cookie', `as_session=${firstToken}`)
        .expect(401);
      await agent.get(`${API}/auth/me`).expect(200);
    });

    it('fijación de sesión: una cookie de sesión impuesta antes del login no sobrevive', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      const pre = await fetchCsrf(agent);
      // el atacante impone un identificador conocido; el servidor no lo adopta
      const imposed = 'A'.repeat(43);
      const res = await agent
        .post(`${API}/auth/login`)
        .set('Cookie', `as_session=${imposed}; as_csrf=${pre}`)
        .set(CSRF_HEADER, pre)
        .send({ email: u.email, password: u.password })
        .expect(200);
      expect(
        cookieValue(
          res.headers['set-cookie'] as unknown as string[],
          'as_session',
        ),
      ).not.toBe(imposed);
      await t
        .browser()
        .get(`${API}/auth/me`)
        .set('Cookie', `as_session=${imposed}`)
        .expect(401);
    });
  });

  describe('caducidad', () => {
    it('sesión con caducidad absoluta vencida → 401, cookie borrada y AUTH_SESSION_REJECTED', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      await login(agent, u);
      await t.prisma.session.updateMany({
        where: { userId: u.id },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      const res = await agent.get(`${API}/auth/me`).expect(401);
      expect(ApiErrorSchema.parse(res.body).code).toBe('UNAUTHENTICATED');
      expect(
        cookieNamed(
          res.headers['set-cookie'] as unknown as string[],
          'as_session',
        ),
      ).toMatch(/Expires=Thu, 01 Jan 1970/i);
      const rows = await auditRows(t.prisma, {
        action: 'AUTH_SESSION_REJECTED',
      });
      expect(
        rows.some(
          (r) => (r.metadata as { reason?: string }).reason === 'expired',
        ),
      ).toBe(true);
    });

    it('sesión inactiva más allá del límite de inactividad → 401', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      await login(agent, u);
      await t.prisma.session.updateMany({
        where: { userId: u.id },
        data: { lastSeenAt: new Date(Date.now() - 31 * 60_000) },
      });
      await agent.get(`${API}/auth/me`).expect(401);
      const rows = await auditRows(t.prisma, {
        action: 'AUTH_SESSION_REJECTED',
      });
      expect(
        rows.some(
          (r) => (r.metadata as { reason?: string }).reason === 'idle_timeout',
        ),
      ).toBe(true);
    });

    it('la actividad dentro del límite mantiene viva la sesión y refresca lastSeenAt', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      await login(agent, u);
      const stale = new Date(Date.now() - 20 * 60_000);
      await t.prisma.session.updateMany({
        where: { userId: u.id },
        data: { lastSeenAt: stale },
      });
      await agent.get(`${API}/auth/me`).expect(200);
      const s = await t.prisma.session.findFirstOrThrow({
        where: { userId: u.id },
      });
      expect(s.lastSeenAt.getTime()).toBeGreaterThan(
        stale.getTime() + 10 * 60_000,
      );
    });

    it('si la cuenta se desactiva, su sesión deja de valer', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      await login(agent, u);
      await t.prisma.user.update({
        where: { id: u.id },
        data: { status: 'DISABLED' },
      });
      await agent.get(`${API}/auth/me`).expect(401);
    });

    it('una cookie con formato inválido se rechaza sin consultar la base', async () => {
      const res = await t
        .browser()
        .get(`${API}/auth/me`)
        .set('Cookie', 'as_session=%27%3B%20DROP%20TABLE')
        .expect(401);
      expect(res.body).toMatchObject({ code: 'UNAUTHENTICATED' });
    });
  });

  describe('cookies con COOKIE_SECURE=true', () => {
    it('usa el prefijo __Host- y el atributo Secure', async () => {
      const secure = await createTestApp({ cookieSecure: true });
      try {
        const u = await createUser(secure.prisma, Role.ISSUER);
        // El agente de pruebas habla HTTP y no reenvía cookies Secure: se envían a mano.
        const pre = await secure.browser().get(`${API}/auth/csrf`).expect(200);
        const csrfCookie = cookieNamed(
          pre.headers['set-cookie'] as unknown as string[],
          '__Host-as_csrf',
        );
        expect(csrfCookie).toBeDefined();
        expect(csrfCookie).toMatch(/;\s*Secure/i);
        expect(csrfCookie).toMatch(/;\s*HttpOnly/i);
        expect(csrfCookie).toMatch(/;\s*SameSite=Strict/i);
        expect(csrfCookie).toMatch(/;\s*Path=\//i);
        expect(csrfCookie).not.toMatch(/Domain=/i);
        const token = (pre.body as { csrfToken: string }).csrfToken;

        const res = await secure
          .browser()
          .post(`${API}/auth/login`)
          .set('Cookie', `__Host-as_csrf=${token}`)
          .set(CSRF_HEADER, token)
          .send({ email: u.email, password: u.password })
          .expect(200);
        const cookies = res.headers['set-cookie'] as unknown as string[];
        const session = cookieNamed(cookies, '__Host-as_session');
        expect(session).toMatch(/;\s*Secure/i);
        expect(session).toMatch(/;\s*HttpOnly/i);
        expect(session).toMatch(/;\s*SameSite=Strict/i);
        expect(session).toMatch(/;\s*Path=\//i);
        expect(session).not.toMatch(/Domain=/i);
        expect(cookieNamed(cookies, 'as_session')).toBeUndefined();
      } finally {
        await secure.close();
      }
    });
  });
});
