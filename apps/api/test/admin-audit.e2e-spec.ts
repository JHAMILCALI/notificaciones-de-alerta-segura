import { Logger } from '@nestjs/common';
import { Role } from '@alertasegura/database';
import {
  ApiErrorSchema,
  AuditListResponseSchema,
  CSRF_HEADER,
  DraftListResponseSchema,
  DraftResponseSchema,
  HealthResponseSchema,
  ProvisionIssuerResponseSchema,
  UserListResponseSchema,
} from '@alertasegura/shared';
import {
  API,
  auditRows,
  createTestApp,
  createUser,
  fetchCsrf,
  login,
  loggedInBrowser,
  type TestApp,
} from './support/app';

describe('Provisión de emisores (solo ADMIN)', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });

  const newIssuer = (suffix: string) => ({
    email: `nuevo-${suffix}-${Date.now()}@test.local`,
    displayName: 'Emisor Nuevo',
    password: 'contraseña-larga-segura-1',
  });

  it('ADMIN con CSRF crea un ISSUER: 201, rol fijado por el servidor, Argon2id y auditoría', async () => {
    const admin = await createUser(t.prisma, Role.ADMIN);
    const { agent, csrfToken } = await loggedInBrowser(t, admin);
    const body = newIssuer('ok');
    const res = await agent
      .post(`${API}/admin/issuers`)
      .set(CSRF_HEADER, csrfToken)
      .send(body)
      .expect(201);
    const { user } = ProvisionIssuerResponseSchema.parse(res.body);
    expect(user).toMatchObject({
      email: body.email,
      displayName: body.displayName,
      role: 'ISSUER',
      status: 'ACTIVE',
    });
    expect(JSON.stringify(res.body)).not.toMatch(
      /passwordHash|argon2|contraseña-larga/i,
    );

    const row = await t.prisma.user.findUniqueOrThrow({
      where: { id: user.id },
    });
    expect(row.passwordHash.startsWith('$argon2id$')).toBe(true);
    expect(row.createdById).toBe(admin.id);

    const audit = await auditRows(t.prisma, {
      actorId: admin.id,
      action: 'ISSUER_PROVISIONED',
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      outcome: 'SUCCESS',
      targetType: 'user',
      targetId: user.id,
    });
    expect(JSON.stringify(audit)).not.toContain(body.password);

    // el emisor creado puede iniciar sesión
    const issuerAgent = t.browser();
    const { body: loginBody } = await login(issuerAgent, {
      email: body.email,
      password: body.password,
    });
    expect(loginBody.user.role).toBe('ISSUER');
  });

  it('un correo repetido (en cualquier capitalización) → 409 CONFLICT', async () => {
    const admin = await createUser(t.prisma, Role.ADMIN);
    const { agent, csrfToken } = await loggedInBrowser(t, admin);
    const body = newIssuer('dup');
    await agent
      .post(`${API}/admin/issuers`)
      .set(CSRF_HEADER, csrfToken)
      .send(body)
      .expect(201);
    const res = await agent
      .post(`${API}/admin/issuers`)
      .set(CSRF_HEADER, csrfToken)
      .send({ ...body, email: body.email.toUpperCase() })
      .expect(409);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 409,
      code: 'CONFLICT',
    });
  });

  it.each([Role.ISSUER, Role.AUDITOR] as const)(
    '%s no puede provisionar emisores → 403 FORBIDDEN',
    async (role) => {
      const u = await createUser(t.prisma, role);
      const { agent, csrfToken } = await loggedInBrowser(t, u);
      const body = newIssuer(role);
      const res = await agent
        .post(`${API}/admin/issuers`)
        .set(CSRF_HEADER, csrfToken)
        .send(body)
        .expect(403);
      expect(res.body).toMatchObject({ code: 'FORBIDDEN' });
      expect(
        await t.prisma.user.findUnique({ where: { email: body.email } }),
      ).toBeNull();
      const audit = await auditRows(t.prisma, {
        actorId: u.id,
        action: 'ACCESS_DENIED',
      });
      expect(audit.length).toBeGreaterThan(0);
    },
  );

  it('anónimo → 401 y ADMIN sin CSRF → 403 CSRF_INVALID', async () => {
    await t
      .browser()
      .post(`${API}/admin/issuers`)
      .send(newIssuer('anon'))
      .expect(401);
    const admin = await createUser(t.prisma, Role.ADMIN);
    const { agent } = await loggedInBrowser(t, admin);
    const res = await agent
      .post(`${API}/admin/issuers`)
      .send(newIssuer('nocsrf'))
      .expect(403);
    expect(res.body).toMatchObject({ code: 'CSRF_INVALID' });
  });

  it('un campo extra `role` (escalada de privilegios) → 400 VALIDATION_FAILED', async () => {
    const admin = await createUser(t.prisma, Role.ADMIN);
    const { agent, csrfToken } = await loggedInBrowser(t, admin);
    const body = { ...newIssuer('role'), role: 'ADMIN' };
    const res = await agent
      .post(`${API}/admin/issuers`)
      .set(CSRF_HEADER, csrfToken)
      .send(body)
      .expect(400);
    const err = ApiErrorSchema.parse(res.body);
    expect(err.code).toBe('VALIDATION_FAILED');
    expect(err.issues?.length).toBeGreaterThan(0);
    expect(
      await t.prisma.user.findUnique({ where: { email: body.email } }),
    ).toBeNull();
  });

  it('entrada inválida → 400 con issues que no repiten los valores enviados', async () => {
    const admin = await createUser(t.prisma, Role.ADMIN);
    const { agent, csrfToken } = await loggedInBrowser(t, admin);
    const secret = 'corta';
    const res = await agent
      .post(`${API}/admin/issuers`)
      .set(CSRF_HEADER, csrfToken)
      .send({ email: 'no-es-correo', displayName: 'x', password: secret })
      .expect(400);
    const err = ApiErrorSchema.parse(res.body);
    expect(err.issues?.map((i) => i.path).sort()).toEqual([
      'body.displayName',
      'body.email',
      'body.password',
    ]);
    expect(JSON.stringify(res.body)).not.toContain(secret);
    expect(JSON.stringify(res.body)).not.toContain('no-es-correo');
    await agent
      .post(`${API}/admin/issuers`)
      .set(CSRF_HEADER, csrfToken)
      .expect(400); // sin cuerpo
  });

  it('GET /admin/users: ADMIN lista sin passwordHash; AUDITOR e ISSUER → 403', async () => {
    const admin = await createUser(t.prisma, Role.ADMIN);
    const { agent } = await loggedInBrowser(t, admin);
    const res = await agent.get(`${API}/admin/users`).expect(200);
    const { users } = UserListResponseSchema.parse(res.body);
    expect(users.some((u) => u.id === admin.id)).toBe(true);
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|argon2/i);
    for (const role of [Role.AUDITOR, Role.ISSUER] as const) {
      const u = await createUser(t.prisma, role);
      const b = await loggedInBrowser(t, u);
      await b.agent.get(`${API}/admin/users`).expect(403);
    }
  });
});

describe('Borradores y autorización por propiedad', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });

  const draftBody = {
    title: 'Alerta de prueba',
    body: 'Texto suficiente de la alerta de prueba',
    severity: 'CRITICAL',
  };

  it('ISSUER crea, lista y lee sus borradores; no ve los ajenos', async () => {
    const a = await createUser(t.prisma, Role.ISSUER);
    const b = await createUser(t.prisma, Role.ISSUER);
    const A = await loggedInBrowser(t, a);
    const B = await loggedInBrowser(t, b);

    const created = await A.agent
      .post(`${API}/drafts`)
      .set(CSRF_HEADER, A.csrfToken)
      .send(draftBody)
      .expect(201);
    const { draft } = DraftResponseSchema.parse(created.body);
    expect(draft).toMatchObject({
      ...draftBody,
      ownerId: a.id,
      status: 'DRAFT',
    });

    await B.agent
      .post(`${API}/drafts`)
      .set(CSRF_HEADER, B.csrfToken)
      .send(draftBody)
      .expect(201);

    const listA = DraftListResponseSchema.parse(
      (await A.agent.get(`${API}/drafts`).expect(200)).body,
    );
    expect(listA.drafts.map((d) => d.id)).toEqual([draft.id]);
    DraftResponseSchema.parse(
      (await A.agent.get(`${API}/drafts/${draft.id}`).expect(200)).body,
    );

    const forbidden = await B.agent
      .get(`${API}/drafts/${draft.id}`)
      .expect(403);
    expect(forbidden.body).toMatchObject({ code: 'FORBIDDEN' });

    const audit = await auditRows(t.prisma, {
      actorId: a.id,
      action: 'DRAFT_CREATED',
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ targetType: 'draft', targetId: draft.id });
  });

  it('ADMIN y AUDITOR no crean ni leen borradores → 403', async () => {
    for (const role of [Role.ADMIN, Role.AUDITOR] as const) {
      const u = await createUser(t.prisma, role);
      const { agent, csrfToken } = await loggedInBrowser(t, u);
      await agent
        .post(`${API}/drafts`)
        .set(CSRF_HEADER, csrfToken)
        .send(draftBody)
        .expect(403);
      await agent.get(`${API}/drafts`).expect(403);
    }
  });

  it('crear sin CSRF → 403 CSRF_INVALID; entrada inválida o con campos extra → 400', async () => {
    const u = await createUser(t.prisma, Role.ISSUER);
    const { agent, csrfToken } = await loggedInBrowser(t, u);
    expect(
      (await agent.post(`${API}/drafts`).send(draftBody).expect(403)).body,
    ).toMatchObject({
      code: 'CSRF_INVALID',
    });
    const post = (payload: unknown) =>
      agent
        .post(`${API}/drafts`)
        .set(CSRF_HEADER, csrfToken)
        .send(payload as object);
    await post({ ...draftBody, title: 'x' }).expect(400);
    await post({ ...draftBody, severity: 'EXTREME' }).expect(400);
    await post({
      ...draftBody,
      ownerId: '00000000-0000-4000-8000-000000000000',
    }).expect(400);
    await post({ ...draftBody, status: 'PUBLISHED' }).expect(400);
    await post({ ...draftBody, body: 'b'.repeat(4001) }).expect(400);
    await agent.get(`${API}/drafts/no-es-uuid`).expect(400);
    expect(await t.prisma.draft.count({ where: { ownerId: u.id } })).toBe(0);
  });

  it('un borrador inexistente → 404', async () => {
    const u = await createUser(t.prisma, Role.ISSUER);
    const { agent } = await loggedInBrowser(t, u);
    const res = await agent
      .get(`${API}/drafts/7f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f`)
      .expect(404);
    expect(res.body).toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('Auditoría: consulta y append-only', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });

  it('ADMIN y AUDITOR leen la auditoría (más recientes primero); ISSUER → 403; anónimo → 401', async () => {
    const issuer = await createUser(t.prisma, Role.ISSUER);
    await loggedInBrowser(t, issuer); // genera AUTH_LOGIN_SUCCEEDED
    for (const role of [Role.ADMIN, Role.AUDITOR] as const) {
      const u = await createUser(t.prisma, role);
      const { agent } = await loggedInBrowser(t, u);
      const res = await agent.get(`${API}/audit?limit=20`).expect(200);
      const { entries } = AuditListResponseSchema.parse(res.body);
      expect(entries.length).toBeGreaterThan(0);
      expect(entries.length).toBeLessThanOrEqual(20);
      const times = entries.map((e) => Date.parse(e.occurredAt));
      expect([...times].sort((x, y) => y - x)).toEqual(times);
      expect(
        entries.some(
          (e) => e.action === 'AUTH_LOGIN_SUCCEEDED' && e.actorId === issuer.id,
        ),
      ).toBe(true);
    }
    const i = await loggedInBrowser(t, issuer);
    await i.agent.get(`${API}/audit`).expect(403);
    await t.browser().get(`${API}/audit`).expect(401);
  });

  it('valida `limit` (1..200) y por defecto devuelve hasta 50', async () => {
    const admin = await createUser(t.prisma, Role.ADMIN);
    const { agent } = await loggedInBrowser(t, admin);
    for (const bad of ['0', '201', 'abc', '-1', '1.5']) {
      await agent.get(`${API}/audit?limit=${bad}`).expect(400);
    }
    const res = await agent.get(`${API}/audit`).expect(200);
    expect(
      AuditListResponseSchema.parse(res.body).entries.length,
    ).toBeLessThanOrEqual(50);
  });

  it('las entradas de auditoría nunca contienen contraseñas, tokens ni cookies', async () => {
    const u = await createUser(t.prisma, Role.ISSUER);
    const agent = t.browser();
    const pre = await fetchCsrf(agent);
    await agent
      .post(`${API}/auth/login`)
      .set(CSRF_HEADER, pre)
      .send({ email: u.email, password: 'x-mala-contraseña' });
    const { csrfToken, setCookie } = await login(agent, u);
    const session = decodeURIComponent(
      (setCookie.find((c) => c.startsWith('as_session=')) as string)
        .split(';')[0]
        .slice(11),
    );
    const all = JSON.stringify(await t.prisma.auditLog.findMany());
    for (const secret of [
      u.password,
      'x-mala-contraseña',
      csrfToken,
      pre,
      session,
    ]) {
      expect(all).not.toContain(secret);
    }
  });

  it('trigger append-only: UPDATE y DELETE sobre AuditLog fallan en PostgreSQL', async () => {
    const entry = await t.prisma.auditLog.create({
      data: {
        action: 'AUTH_LOGOUT',
        outcome: 'SUCCESS',
        metadata: { prueba: true },
      },
    });
    await expect(
      t.prisma.auditLog.update({
        where: { id: entry.id },
        data: { action: 'ACCESS_DENIED' },
      }),
    ).rejects.toThrow(/append-only/i);
    await expect(
      t.prisma.auditLog.delete({ where: { id: entry.id } }),
    ).rejects.toThrow(/append-only/i);
    await expect(
      t.prisma
        .$executeRaw`UPDATE "AuditLog" SET "outcome" = 'DENIED' WHERE "id" = ${entry.id}::uuid`,
    ).rejects.toThrow(/append-only/i);
    await expect(t.prisma.$executeRaw`DELETE FROM "AuditLog"`).rejects.toThrow(
      /append-only/i,
    );
    await expect(t.prisma.auditLog.deleteMany({})).rejects.toThrow(
      /append-only/i,
    );
    await expect(
      t.prisma.$executeRawUnsafe('TRUNCATE TABLE "AuditLog"'),
    ).rejects.toThrow(/append-only/i);
    const still = await t.prisma.auditLog.findUniqueOrThrow({
      where: { id: entry.id },
    });
    expect(still).toMatchObject({ action: 'AUTH_LOGOUT', outcome: 'SUCCESS' });
  });

  it('una caída de la auditoría no tumba la petición, pero queda en el log del servidor', async () => {
    const errorLog = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const create = jest
      .spyOn(t.prisma.auditLog, 'create')
      .mockRejectedValue(new Error('PG caído'));
    try {
      const agent = t.browser();
      const pre = await fetchCsrf(agent);
      const res = await agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, pre)
        .send({
          email: 'sin-auditoria@test.local',
          password: 'mala-contraseña',
        });
      expect(res.status).toBe(401); // la respuesta es la de siempre, no 500
      expect(create).toHaveBeenCalled();
      expect(errorLog).toHaveBeenCalledWith(
        expect.stringContaining('FALLO DE AUDITORIA'),
      );
    } finally {
      create.mockRestore();
      errorLog.mockRestore();
    }
  });
});

describe('Robustez HTTP: errores, cabeceras y salud', () => {
  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(async () => {
    await t.close();
  });

  it('GET /health → 200 con el contrato HealthResponse', async () => {
    const res = await t.browser().get(`${API}/health`).expect(200);
    expect(HealthResponseSchema.parse(res.body)).toEqual({
      status: 'ok',
      database: 'up',
    });
  });

  it('GET /health → 503 degraded si PostgreSQL no responde', async () => {
    const spy = jest
      .spyOn(t.prisma, '$queryRaw')
      .mockRejectedValue(new Error('conexión rechazada'));
    try {
      const res = await t.browser().get(`${API}/health`).expect(503);
      expect(HealthResponseSchema.parse(res.body)).toEqual({
        status: 'degraded',
        database: 'down',
      });
      expect(JSON.stringify(res.body)).not.toContain('conexión');
    } finally {
      spy.mockRestore();
    }
  });

  it('un fallo inesperado devuelve 500 INTERNAL_ERROR sin trazas ni detalles de Prisma', async () => {
    const errorLog = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const spy = jest
      .spyOn(t.prisma.draft, 'findMany')
      .mockRejectedValue(
        new Error(
          'Invalid `prisma.draft.findMany()` invocation: relation "Draft" at C:\\secret\\path.ts:12',
        ),
      );
    try {
      const issuer = await createUser(t.prisma, Role.ISSUER);
      const { agent } = await loggedInBrowser(t, issuer);
      const res = await agent.get(`${API}/drafts`).expect(500);
      expect(ApiErrorSchema.parse(res.body)).toEqual({
        statusCode: 500,
        code: 'INTERNAL_ERROR',
        message: 'Error interno del servidor',
      });
      const dump = JSON.stringify(res.body) + JSON.stringify(res.headers);
      expect(dump).not.toMatch(/prisma|secret|path\.ts|stack|relation/i);
      expect(errorLog).toHaveBeenCalled(); // la traza solo queda en el log
    } finally {
      spy.mockRestore();
      errorLog.mockRestore();
    }
  });

  it('JSON malformado → 400 ApiError; cuerpo > 100 kb → 413; ruta inexistente → 404 ApiError', async () => {
    const agent = t.browser();
    const bad = await agent
      .post(`${API}/auth/login`)
      .set('Content-Type', 'application/json')
      .send('{"email":')
      .expect(400);
    expect(ApiErrorSchema.parse(bad.body).code).toBe('VALIDATION_FAILED');
    expect(JSON.stringify(bad.body)).not.toMatch(/SyntaxError|Unexpected|at /);

    const big = await agent
      .post(`${API}/auth/login`)
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ email: 'a@b.co', password: 'x'.repeat(150_000) }))
      .expect(413);
    expect(ApiErrorSchema.parse(big.body).statusCode).toBe(413);

    const nf = await agent.get(`${API}/no-existe`).expect(404);
    expect(ApiErrorSchema.parse(nf.body).code).toBe('NOT_FOUND');
    await agent.get('/').expect(404);
  });

  it('el login rechaza campos extra y tipos incorrectos (strictObject)', async () => {
    const agent = t.browser();
    const pre = await fetchCsrf(agent);
    const post = (payload: unknown) =>
      agent
        .post(`${API}/auth/login`)
        .set(CSRF_HEADER, pre)
        .send(payload as object);
    await post({ email: 'a@b.co', password: 'x', role: 'ADMIN' }).expect(400);
    await post({ email: 'a@b.co', password: 12345 }).expect(400);
    await post({ email: ['a@b.co'], password: 'x' }).expect(400);
    await post({ email: 'a@b.co', password: '' }).expect(400);
    await post({ email: 'a@b.co', password: 'x'.repeat(129) }).expect(400);
    await post({}).expect(400);
    await post({ email: { $ne: null }, password: { $ne: null } }).expect(400); // inyección tipo NoSQL
  });

  it('cabeceras de seguridad: sin X-Powered-By, con helmet y sin CORS', async () => {
    const res = await t
      .browser()
      .get(`${API}/health`)
      .set('Origin', 'https://evil.example')
      .expect(200);
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    const pre = await t
      .browser()
      .options(`${API}/auth/login`)
      .set('Origin', 'https://evil.example')
      .set('Access-Control-Request-Method', 'POST');
    expect(pre.headers['access-control-allow-origin']).toBeUndefined();
  });
});
