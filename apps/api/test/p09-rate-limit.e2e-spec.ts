import { Role } from '@alertasegura/database';
import { ApiErrorSchema, CSRF_HEADER } from '@alertasegura/shared';
import {
  API,
  auditRows,
  createTestApp,
  createUser,
  fetchCsrf,
  loggedInBrowser,
  type TestApp,
} from './support/app';

describe('P09: rate limiting (429 con Retry-After)', () => {
  describe('login por cuenta', () => {
    let t: TestApp;
    beforeAll(async () => {
      t = await createTestApp({
        rateLimits: { loginAccount: { limit: 3, windowSeconds: 900 } },
      });
    });
    afterAll(async () => {
      await t.close();
    });

    const attempt = async (
      agent: ReturnType<TestApp['browser']>,
      email: string,
      password: string,
    ) => {
      const token = await fetchCsrf(agent);
      return agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, token)
        .send({ email, password });
    };

    it('tras 3 fallos el 4.º intento recibe 429 con Retry-After, aunque la contraseña sea la correcta', async () => {
      const victim = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      for (let i = 0; i < 3; i++) {
        await attempt(agent, victim.email, `incorrecta-${i}`).then((r) =>
          expect(r.status).toBe(401),
        );
      }
      const blocked = await attempt(agent, victim.email, victim.password);
      expect(blocked.status).toBe(429);
      expect(ApiErrorSchema.parse(blocked.body)).toMatchObject({
        statusCode: 429,
        code: 'RATE_LIMITED',
      });
      const retryAfter = Number(blocked.headers['retry-after']);
      expect(Number.isInteger(retryAfter)).toBe(true);
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(900);
      expect(blocked.headers['set-cookie']?.toString() ?? '').not.toContain(
        'as_session',
      );

      const rows = await auditRows(t.prisma, {
        action: 'RATE_LIMITED',
        targetId: 'login-account',
      });
      expect(rows.length).toBeGreaterThan(0);
      expect(rows[0]).toMatchObject({ outcome: 'DENIED' });
      expect(rows[0]?.metadata).toMatchObject({
        scope: 'login-account',
        limit: 3,
        windowSeconds: 900,
      });
      // la auditoría no contiene la contraseña ni el correo en claro del bloqueo
      expect(JSON.stringify(rows)).not.toContain(victim.password);
    });

    it('el bloqueo es por cuenta: otra cuenta desde la misma IP sigue pudiendo entrar', async () => {
      const victim = await createUser(t.prisma, Role.ISSUER);
      const bystander = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      for (let i = 0; i < 3; i++)
        await attempt(agent, victim.email, 'mala-' + i);
      expect((await attempt(agent, victim.email, victim.password)).status).toBe(
        429,
      );
      expect(
        (await attempt(t.browser(), bystander.email, bystander.password))
          .status,
      ).toBe(200);
    });

    it('también limita cuentas inexistentes (no revela cuáles existen)', async () => {
      const agent = t.browser();
      const email = 'fantasma@test.local';
      for (let i = 0; i < 3; i++) {
        expect((await attempt(agent, email, 'mala-' + i)).status).toBe(401);
      }
      expect((await attempt(agent, email, 'otra')).status).toBe(429);
    });

    it('el correo se normaliza: mayúsculas no evaden el límite', async () => {
      const victim = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      for (let i = 0; i < 3; i++)
        await attempt(agent, victim.email.toUpperCase(), 'mala-' + i);
      expect((await attempt(agent, victim.email, victim.password)).status).toBe(
        429,
      );
    });

    it('los inicios de sesión correctos NO consumen el cupo (el legítimo no se bloquea a sí mismo)', async () => {
      const admin = await createUser(t.prisma, Role.ADMIN);
      for (let i = 0; i < 8; i++) {
        const res = await attempt(t.browser(), admin.email, admin.password);
        expect(res.status).toBe(200);
      }
    });

    it('con el contador a 2 fallos, un login correcto sigue funcionando y el 3.er fallo todavía da 401', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const agent = t.browser();
      await attempt(agent, u.email, 'mala-1');
      await attempt(agent, u.email, 'mala-2');
      expect((await attempt(agent, u.email, u.password)).status).toBe(200);
      expect((await attempt(t.browser(), u.email, 'mala-3')).status).toBe(401);
      expect((await attempt(t.browser(), u.email, u.password)).status).toBe(
        429,
      );
    });
  });

  describe('login por IP', () => {
    let t: TestApp;
    beforeAll(async () => {
      t = await createTestApp({
        rateLimits: { loginIp: { limit: 3, windowSeconds: 60 } },
      });
    });
    afterAll(async () => {
      await t.close();
    });

    it('el 4.º intento de login desde la misma IP recibe 429 con Retry-After (cuentas distintas)', async () => {
      const agent = t.browser();
      const results: number[] = [];
      let last:
        Awaited<ReturnType<ReturnType<TestApp['browser']>['post']>> | undefined;
      for (let i = 0; i < 4; i++) {
        const token = await fetchCsrf(agent);
        last = await agent
          .post(`${API}/auth/login`)
          .set(CSRF_HEADER, token)
          .send({
            email: `usuario-${i}@test.local`,
            password: 'mala-contraseña',
          });
        results.push(last.status);
      }
      expect(results).toEqual([401, 401, 401, 429]);
      expect(ApiErrorSchema.parse(last?.body)).toMatchObject({
        code: 'RATE_LIMITED',
      });
      const retryAfter = Number(last?.headers['retry-after']);
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(60);

      const rows = await auditRows(t.prisma, {
        action: 'RATE_LIMITED',
        targetId: 'login-ip',
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.metadata).toMatchObject({
        scope: 'login-ip',
        limit: 3,
        windowSeconds: 60,
      });
    });

    it('un bloqueo repetido no inunda la auditoría (una entrada por clave y minuto)', async () => {
      const agent = t.browser();
      for (let i = 0; i < 5; i++) {
        const token = await fetchCsrf(agent);
        await agent
          .post(`${API}/auth/login`)
          .set(CSRF_HEADER, token)
          .send({ email: 'x@test.local', password: 'mala-contraseña' })
          .expect(429);
      }
      const rows = await auditRows(t.prisma, {
        action: 'RATE_LIMITED',
        targetId: 'login-ip',
      });
      expect(rows).toHaveLength(1);
    });

    it('las rutas que no son login no consumen el cupo de login', async () => {
      const other = await createTestApp({
        rateLimits: { loginIp: { limit: 2, windowSeconds: 60 } },
      });
      try {
        const agent = other.browser();
        for (let i = 0; i < 10; i++)
          await agent.get(`${API}/health`).expect(200);
        await agent.get(`${API}/auth/csrf`).expect(200);
      } finally {
        await other.close();
      }
    });
  });

  describe('IP del cliente y TRUST_PROXY', () => {
    it('con TRUST_PROXY desactivado X-Forwarded-For no sirve para evadir el límite', async () => {
      const t = await createTestApp({
        rateLimits: { loginIp: { limit: 2, windowSeconds: 60 } },
      });
      try {
        const agent = t.browser();
        const statuses: number[] = [];
        for (let i = 0; i < 3; i++) {
          const token = await fetchCsrf(agent);
          const res = await agent
            .post(`${API}/auth/login`)
            .set('X-Forwarded-For', `203.0.113.${i + 1}`)
            .set(CSRF_HEADER, token)
            .send({ email: 'spoof@test.local', password: 'mala-contraseña' });
          statuses.push(res.status);
        }
        expect(statuses).toEqual([401, 401, 429]);
      } finally {
        await t.close();
      }
    });

    it('con TRUST_PROXY=1 cada IP reenviada tiene su propio cupo', async () => {
      const t = await createTestApp({
        trustProxy: 1,
        rateLimits: { loginIp: { limit: 2, windowSeconds: 60 } },
      });
      try {
        const agent = t.browser();
        const login = async (ip: string) => {
          const token = await fetchCsrf(agent);
          return agent
            .post(`${API}/auth/login`)
            .set('X-Forwarded-For', ip)
            .set(CSRF_HEADER, token)
            .send({ email: 'proxy@test.local', password: 'mala-contraseña' });
        };
        expect((await login('198.51.100.1')).status).toBe(401);
        expect((await login('198.51.100.1')).status).toBe(401);
        expect((await login('198.51.100.1')).status).toBe(429);
        expect((await login('198.51.100.2')).status).toBe(401); // otra IP, cupo propio
        const rows = await auditRows(t.prisma, {
          action: 'RATE_LIMITED',
          targetId: 'login-ip',
        });
        expect(rows.some((r) => r.ip === '198.51.100.1')).toBe(true);
      } finally {
        await t.close();
      }
    });
  });

  describe('usuario autenticado', () => {
    let t: TestApp;
    beforeAll(async () => {
      t = await createTestApp({
        rateLimits: { user: { limit: 5, windowSeconds: 60 } },
      });
    });
    afterAll(async () => {
      await t.close();
    });

    it('la 6.ª petición autenticada en la ventana recibe 429 con Retry-After', async () => {
      const u = await createUser(t.prisma, Role.ISSUER);
      const { agent } = await loggedInBrowser(t, u);
      const statuses: number[] = [];
      let last: { headers: Record<string, unknown>; body: unknown } | undefined;
      for (let i = 0; i < 6; i++) {
        const res = await agent.get(`${API}/auth/me`);
        statuses.push(res.status);
        last = res;
      }
      expect(statuses).toEqual([200, 200, 200, 200, 200, 429]);
      expect(ApiErrorSchema.parse(last?.body)).toMatchObject({
        statusCode: 429,
        code: 'RATE_LIMITED',
      });
      const retryAfter = Number(last?.headers['retry-after']);
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(60);

      const rows = await auditRows(t.prisma, {
        actorId: u.id,
        action: 'RATE_LIMITED',
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]?.metadata).toMatchObject({
        scope: 'user',
        limit: 5,
        windowSeconds: 60,
      });
    });

    it('el límite es por usuario: otro usuario autenticado no se ve afectado', async () => {
      const a = await createUser(t.prisma, Role.ISSUER);
      const b = await createUser(t.prisma, Role.AUDITOR);
      const { agent: agentA } = await loggedInBrowser(t, a);
      const { agent: agentB } = await loggedInBrowser(t, b);
      for (let i = 0; i < 5; i++)
        await agentA.get(`${API}/auth/me`).expect(200);
      await agentA.get(`${API}/auth/me`).expect(429);
      await agentB.get(`${API}/auth/me`).expect(200);
    });

    it('el límite sigue al usuario aunque abra otra sesión', async () => {
      const a = await createUser(t.prisma, Role.ISSUER);
      const first = await loggedInBrowser(t, a);
      for (let i = 0; i < 5; i++)
        await first.agent.get(`${API}/auth/me`).expect(200);
      const second = await loggedInBrowser(t, a);
      await second.agent.get(`${API}/auth/me`).expect(429);
    });
  });

  describe('límite global por IP', () => {
    it('superado el límite global, incluso rutas públicas responden 429', async () => {
      const t = await createTestApp({
        rateLimits: { global: { limit: 4, windowSeconds: 60 } },
      });
      try {
        const agent = t.browser();
        const statuses: number[] = [];
        for (let i = 0; i < 5; i++)
          statuses.push((await agent.get(`${API}/health`)).status);
        expect(statuses).toEqual([200, 200, 200, 200, 429]);
        const res = await agent.get(`${API}/health`).expect(429);
        expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
      } finally {
        await t.close();
      }
    });
  });
});
