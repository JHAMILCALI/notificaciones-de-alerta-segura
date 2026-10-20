import { randomUUID } from 'node:crypto';
import { Role } from '@alertasegura/database';
import {
  ApiErrorSchema,
  CSRF_HEADER,
  DraftListResponseSchema,
} from '@alertasegura/shared';
import {
  API,
  WEB_ORIGIN,
  auditRows,
  createTestApp,
  createUser,
  fetchCsrf,
  loggedInBrowser,
  type TestApp,
  type TestUser,
} from './support/app';

describe('P02a: un anónimo no puede publicar (401)', () => {
  let t: TestApp;
  let owner: TestUser;
  let draftId: string;

  beforeAll(async () => {
    t = await createTestApp();
    owner = await createUser(t.prisma, Role.ISSUER);
    const draft = await t.prisma.draft.create({
      data: {
        title: 'Borrador de prueba',
        body: 'Cuerpo del borrador de prueba',
        severity: 'INFO',
        ownerId: owner.id,
      },
    });
    draftId = draft.id;
  });
  afterAll(async () => {
    await t.close();
  });

  it('sin token CSRF → 401 UNAUTHENTICATED', async () => {
    const res = await t
      .browser()
      .post(`${API}/drafts/${draftId}/publish`)
      .expect(401);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 401,
      code: 'UNAUTHENTICATED',
    });
  });

  it('con un token CSRF anónimo válido → 401 (nunca 403 ni 501)', async () => {
    const agent = t.browser();
    const token = await fetchCsrf(agent);
    const res = await agent
      .post(`${API}/drafts/${draftId}/publish`)
      .set(CSRF_HEADER, token)
      .expect(401);
    expect(res.body).toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('con un token CSRF inventado → 401', async () => {
    const res = await t
      .browser()
      .post(`${API}/drafts/${draftId}/publish`)
      .set(CSRF_HEADER, 'inventado.inventado')
      .expect(401);
    expect(res.body).toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('el 401 no depende de que el borrador exista ni de que el id sea válido', async () => {
    await t.browser().post(`${API}/drafts/${randomUUID()}/publish`).expect(401);
    await t.browser().post(`${API}/drafts/no-es-uuid/publish`).expect(401);
  });

  it('el resto de rutas protegidas también devuelven 401 a un anónimo', async () => {
    const agent = t.browser();
    await agent.get(`${API}/auth/me`).expect(401);
    await agent.get(`${API}/drafts`).expect(401);
    await agent.get(`${API}/drafts/${draftId}`).expect(401);
    await agent.get(`${API}/admin/users`).expect(401);
    await agent.get(`${API}/audit`).expect(401);
    await agent.post(`${API}/drafts`).send({}).expect(401);
    await agent.post(`${API}/admin/issuers`).send({}).expect(401);
  });

  it('audita el acceso denegado sin actor', async () => {
    await t.browser().post(`${API}/drafts/${draftId}/publish`).expect(401);
    const rows = await t.prisma.auditLog.findMany({
      where: { action: 'ACCESS_DENIED', actorId: null },
    });
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0]).toMatchObject({ outcome: 'DENIED' });
    expect(
      rows.some(
        (r) => (r.metadata as { reason?: string }).reason === 'unauthenticated',
      ),
    ).toBe(true);
  });
});

describe('P02b: usuarios autenticados sin derecho no publican', () => {
  let t: TestApp;
  let owner: TestUser;
  let otherIssuer: TestUser;
  let auditor: TestUser;
  let admin: TestUser;
  let draftId: string;

  beforeAll(async () => {
    t = await createTestApp();
    owner = await createUser(t.prisma, Role.ISSUER);
    otherIssuer = await createUser(t.prisma, Role.ISSUER);
    auditor = await createUser(t.prisma, Role.AUDITOR);
    admin = await createUser(t.prisma, Role.ADMIN);
    const draft = await t.prisma.draft.create({
      data: {
        title: 'Borrador del propietario',
        body: 'Cuerpo del borrador del propietario',
        severity: 'WARNING',
        ownerId: owner.id,
      },
    });
    draftId = draft.id;
  });
  afterAll(async () => {
    await t.close();
  });

  const publish = (
    agent: ReturnType<TestApp['browser']>,
    csrf: string | null,
    id = draftId,
  ) => {
    const req = agent.post(`${API}/drafts/${id}/publish`);
    return csrf === null ? req : req.set(CSRF_HEADER, csrf);
  };

  it('AUDITOR autenticado → 403 FORBIDDEN y PUBLICATION_DENIED', async () => {
    const { agent, csrfToken } = await loggedInBrowser(t, auditor);
    const res = await publish(agent, csrfToken).expect(403);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 403,
      code: 'FORBIDDEN',
    });
    const rows = await auditRows(t.prisma, {
      actorId: auditor.id,
      action: 'PUBLICATION_DENIED',
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ outcome: 'DENIED', targetType: null });
    expect(rows[0]?.metadata).toMatchObject({
      reason: 'missing_permission',
      role: 'AUDITOR',
    });
  });

  it('ADMIN autenticado → 403 FORBIDDEN (administra cuentas, no publica)', async () => {
    const { agent, csrfToken } = await loggedInBrowser(t, admin);
    const res = await publish(agent, csrfToken).expect(403);
    expect(res.body).toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    const rows = await auditRows(t.prisma, {
      actorId: admin.id,
      action: 'PUBLICATION_DENIED',
    });
    expect(rows).toHaveLength(1);
  });

  it('ISSUER que no es propietario → 403 FORBIDDEN y PUBLICATION_DENIED con el borrador como objetivo', async () => {
    const { agent, csrfToken } = await loggedInBrowser(t, otherIssuer);
    const res = await publish(agent, csrfToken).expect(403);
    expect(res.body).toMatchObject({ statusCode: 403, code: 'FORBIDDEN' });
    const rows = await auditRows(t.prisma, {
      actorId: otherIssuer.id,
      action: 'PUBLICATION_DENIED',
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ targetType: 'draft', targetId: draftId });
    expect(rows[0]?.metadata).toMatchObject({ reason: 'not_owner' });
  });

  it('ISSUER propietario con CSRF → 501 PUBLICATION_NOT_IMPLEMENTED y PUBLICATION_AUTHORIZED', async () => {
    const { agent, csrfToken } = await loggedInBrowser(t, owner);
    const res = await publish(agent, csrfToken).expect(501);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 501,
      code: 'PUBLICATION_NOT_IMPLEMENTED',
    });
    const rows = await auditRows(t.prisma, {
      actorId: owner.id,
      action: 'PUBLICATION_AUTHORIZED',
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      outcome: 'SUCCESS',
      targetType: 'draft',
      targetId: draftId,
    });
    // No se simula nada: el borrador sigue siendo un borrador, sin alerta publicada.
    const draft = await t.prisma.draft.findUniqueOrThrow({
      where: { id: draftId },
    });
    expect(draft.status).toBe('DRAFT');
  });

  it('sin CSRF → 403 CSRF_INVALID, incluso para el propietario (el CSRF va antes que el RBAC)', async () => {
    const owned = await loggedInBrowser(t, owner);
    const res = await publish(owned.agent, null).expect(403);
    expect(res.body).toMatchObject({ statusCode: 403, code: 'CSRF_INVALID' });

    const aud = await loggedInBrowser(t, auditor);
    const res2 = await publish(aud.agent, null).expect(403);
    expect(res2.body).toMatchObject({ code: 'CSRF_INVALID' }); // no FORBIDDEN

    const rows = await auditRows(t.prisma, {
      actorId: owner.id,
      action: 'CSRF_REJECTED',
    });
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0]?.metadata).toMatchObject({ reason: 'token_missing' });
  });

  it('CSRF alterado, de otra sesión o con Origin ajeno → 403 CSRF_INVALID', async () => {
    const { agent, csrfToken } = await loggedInBrowser(t, owner);
    const other = await loggedInBrowser(t, owner); // otra sesión del mismo usuario

    const altered = `${csrfToken.slice(0, -2)}${csrfToken.endsWith('AA') ? 'BB' : 'AA'}`;
    await publish(agent, altered).expect(403);

    // cabecera válida de otra sesión, pero la cookie del navegador es la propia
    await publish(agent, other.csrfToken).expect(403);

    // token anónimo (emitido antes de iniciar sesión) usado con sesión
    const anonAgent = t.browser();
    const anonToken = await fetchCsrf(anonAgent);
    await publish(agent, anonToken).expect(403);

    const res = await publish(agent, csrfToken)
      .set('Origin', 'https://evil.example')
      .expect(403);
    expect(res.body).toMatchObject({ code: 'CSRF_INVALID' });
    const ok = await publish(agent, csrfToken)
      .set('Origin', WEB_ORIGIN)
      .expect(501);
    expect(ok.body).toMatchObject({ code: 'PUBLICATION_NOT_IMPLEMENTED' });
  });

  it('la cabecera CSRF sin la cookie correspondiente no basta (double-submit)', async () => {
    const { csrfToken } = await loggedInBrowser(t, owner);
    // otro navegador con su propia sesión no puede usar el token del primero
    const { agent: intruder } = await loggedInBrowser(t, otherIssuer);
    await publish(intruder, csrfToken).expect(403);
  });

  it('ISSUER propietario: borrador inexistente → 404 NOT_FOUND', async () => {
    const { agent, csrfToken } = await loggedInBrowser(t, owner);
    const res = await publish(agent, csrfToken, randomUUID()).expect(404);
    expect(res.body).toMatchObject({ code: 'NOT_FOUND' });
  });

  it('orden de controles: la validación (400) va antes que el RBAC (403)', async () => {
    const { agent, csrfToken } = await loggedInBrowser(t, auditor);
    const res = await publish(agent, csrfToken, 'no-es-uuid').expect(400);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      code: 'VALIDATION_FAILED',
    });
    expect(ApiErrorSchema.parse(res.body).issues?.[0]).toMatchObject({
      path: 'params.draftId',
    });
    // sin existencia de borrador, el RBAC sigue negando antes que el 404
    await publish(agent, csrfToken, randomUUID()).expect(403);
  });

  it('los emisores no publican con un método distinto ni leen borradores ajenos', async () => {
    const { agent } = await loggedInBrowser(t, otherIssuer);
    await agent.get(`${API}/drafts/${draftId}`).expect(403);
    const list = await agent.get(`${API}/drafts`).expect(200);
    expect(DraftListResponseSchema.parse(list.body).drafts).toEqual([]);
  });
});
