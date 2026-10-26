import { Role } from '@alertasegura/database';
import {
  AlertaResponseSchema,
  ApiErrorSchema,
  CSRF_HEADER,
  type AlertaPublicada,
} from '@alertasegura/shared';
import {
  API,
  auditRows,
  createTestApp,
  createUser,
  fetchCsrf,
  loggedInBrowser,
  type TestApp,
  type TestUser,
} from './support/app';
import {
  apiCancel,
  apiPublishNew,
  decodeB64u,
  sha256Hex,
  type Session,
} from './support/alerts';
import { expectValid, verifyWithPackage } from './support/verify';

describe('P02c / S2-22: cancelar una alerta exige ser su emisor', () => {
  let t: TestApp;
  let owner: TestUser;
  let other: TestUser;
  let ownerSession: Session;
  let otherSession: Session;

  beforeAll(async () => {
    t = await createTestApp();
    owner = await createUser(t.prisma, Role.ISSUER);
    other = await createUser(t.prisma, Role.ISSUER);
    ownerSession = await loggedInBrowser(t, owner);
    otherSession = await loggedInBrowser(t, other);
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(() => {
    t.signer.reset();
  });

  const newAlert = (): Promise<AlertaPublicada> => apiPublishNew(ownerSession);
  const eventosOf = (alertaId: string) =>
    t.owner.eventoAlerta.findMany({ where: { alertaId } });

  it('el emisor dueño → 201 con EVENTO y ESTADO CANCELADA firmados, encadenados por hash y verificables', async () => {
    t.clock.set(new Date('2026-10-26T15:00:00Z'));
    const alerta = await newAlert();
    t.clock.set(new Date('2026-10-26T15:20:30Z'));

    const res = await apiCancel(ownerSession, alerta.id).expect(201);
    const cancelada = AlertaResponseSchema.parse(res.body).alerta;
    expect(cancelada.id).toBe(alerta.id);
    expect(cancelada.eventos).toHaveLength(1);
    // la alerta original no cambia: mismos bytes, mismo hash y misma firma
    expect(cancelada.alerta).toEqual(alerta.alerta);

    const [evento] = cancelada.eventos;
    const [vAlerta, vEvento, vEstado] = verifyWithPackage(
      [cancelada.alerta, evento, cancelada.estado],
      t.signer.publicJwk,
    );
    for (const v of [vAlerta, vEvento, vEstado]) {
      expectValid(v);
    }
    expect(vEvento?.document).toMatchObject({
      tipo_doc: 'EVENTO',
      alerta_id: alerta.id,
      emisor_id: owner.id,
      accion: 'CANCELACION',
      emitida_en: '2026-10-26T15:20:30Z',
      // el evento apunta a la alerta exacta: SHA-256 de sus bytes canónicos
      hash_alerta: alerta.alerta.hash_payload,
    });
    expect(vEstado?.document).toMatchObject({
      tipo_doc: 'ESTADO',
      alerta_id: alerta.id,
      estado: 'CANCELADA',
      secuencia: 1,
      issued_at: '2026-10-26T15:20:30Z',
      expires_at: '2026-10-26T15:30:30Z',
      ultimo_evento_hash: evento?.hash_payload,
    });

    // lo guardado son los bytes exactos del firmante
    const [row] = await eventosOf(alerta.id);
    expect(
      Buffer.compare(
        Buffer.from(row?.payloadCanonico ?? []),
        decodeB64u(evento?.payload_canonico ?? ''),
      ),
    ).toBe(0);
    expect(row).toMatchObject({
      hashEvento: sha256Hex(decodeB64u(evento?.payload_canonico ?? '')),
      hashAlerta: alerta.alerta.hash_payload,
    });
    const estados = await t.owner.estadoAlerta.findMany({
      where: { alertaId: alerta.id },
      orderBy: { secuencia: 'asc' },
    });
    expect(estados.map((e) => e.secuencia)).toEqual([0, 1]); // el estado anterior se conserva (append-only)

    const audit = await auditRows(t.prisma, {
      action: 'ALERT_CANCELLED',
      targetId: alerta.id,
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ outcome: 'SUCCESS', actorId: owner.id });
    expect(t.signer.calls.map((c) => c.tipo_doc)).toEqual([
      'ALERTA',
      'ESTADO',
      'EVENTO',
      'ESTADO',
    ]);
  });

  it('otro emisor → 403 FORBIDDEN y CANCEL_DENIED; no se firma ni se guarda nada', async () => {
    const alerta = await newAlert();
    const calls = t.signer.calls.length;

    const res = await apiCancel(otherSession, alerta.id).expect(403);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 403,
      code: 'FORBIDDEN',
    });
    const denied = await auditRows(t.prisma, {
      action: 'CANCEL_DENIED',
      actorId: other.id,
      targetId: alerta.id,
    });
    expect(denied).toHaveLength(1);
    expect(denied[0]).toMatchObject({
      outcome: 'DENIED',
      targetType: 'alerta',
    });
    expect(denied[0]?.metadata).toMatchObject({ reason: 'not_owner' });

    expect(t.signer.calls).toHaveLength(calls);
    expect(await eventosOf(alerta.id)).toHaveLength(0);
    expect(
      await auditRows(t.prisma, {
        action: 'ALERT_CANCELLED',
        targetId: alerta.id,
      }),
    ).toHaveLength(0);
    // y la alerta sigue vigente para su dueño
    await apiCancel(ownerSession, alerta.id).expect(201);
  });

  it.each([Role.ADMIN, Role.AUDITOR] as const)(
    '%s → 403 FORBIDDEN y CANCEL_DENIED (no tiene el permiso alerts:cancel)',
    async (role) => {
      const alerta = await newAlert();
      const user = await createUser(t.prisma, role);
      const session = await loggedInBrowser(t, user);
      await apiCancel(session, alerta.id).expect(403);
      const denied = await auditRows(t.prisma, {
        action: 'CANCEL_DENIED',
        actorId: user.id,
      });
      expect(denied).toHaveLength(1);
      expect(denied[0]?.metadata).toMatchObject({
        reason: 'missing_permission',
        role,
      });
      expect(await eventosOf(alerta.id)).toHaveLength(0);
    },
  );

  it('cancelar dos veces → 409 CONFLICT; una sola cancelación', async () => {
    const alerta = await newAlert();
    await apiCancel(ownerSession, alerta.id).expect(201);
    const calls = t.signer.calls.length;
    const res = await apiCancel(ownerSession, alerta.id).expect(409);
    expect(ApiErrorSchema.parse(res.body).code).toBe('CONFLICT');
    expect(t.signer.calls).toHaveLength(calls);
    expect(await eventosOf(alerta.id)).toHaveLength(1);
  });

  it('dos cancelaciones simultáneas → una 201 y otra 409', async () => {
    const alerta = await newAlert();
    const [a, b] = await Promise.all([
      apiCancel(ownerSession, alerta.id),
      apiCancel(ownerSession, alerta.id),
    ]);
    expect([a.status, b.status].sort()).toEqual([201, 409]);
    expect(await eventosOf(alerta.id)).toHaveLength(1);
  });

  it('alerta inexistente → 404; id inválido → 400; cuerpo con campos extra → 400', async () => {
    const missing = '7f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f';
    expect(
      (await apiCancel(ownerSession, missing).expect(404)).body,
    ).toMatchObject({
      code: 'NOT_FOUND',
    });
    await apiCancel(ownerSession, 'no-es-uuid').expect(400);
    const alerta = await newAlert();
    await ownerSession.agent
      .post(`${API}/alerts/${alerta.id}/cancel`)
      .set(CSRF_HEADER, ownerSession.csrfToken)
      .send({ motivo: 'x' })
      .expect(400);
    expect(await eventosOf(alerta.id)).toHaveLength(0);
  });

  it('sin sesión → 401; con sesión pero sin CSRF → 403 CSRF_INVALID', async () => {
    const alerta = await newAlert();
    const anon = t.browser();
    const token = await fetchCsrf(anon);
    await anon
      .post(`${API}/alerts/${alerta.id}/cancel`)
      .set(CSRF_HEADER, token)
      .send({})
      .expect(401);
    const res = await ownerSession.agent
      .post(`${API}/alerts/${alerta.id}/cancel`)
      .send({})
      .expect(403);
    expect(res.body).toMatchObject({ code: 'CSRF_INVALID' });
    expect(await eventosOf(alerta.id)).toHaveLength(0);
  });

  it('firmante caído → 503 SIGNER_UNAVAILABLE, CANCEL_FAILED y la alerta NO queda cancelada; luego se puede reintentar', async () => {
    const alerta = await newAlert();
    t.signer.fault = 'down';
    const res = await apiCancel(ownerSession, alerta.id).expect(503);
    expect(res.body).toMatchObject({ code: 'SIGNER_UNAVAILABLE' });
    expect(await eventosOf(alerta.id)).toHaveLength(0);
    const failed = await auditRows(t.prisma, {
      action: 'CANCEL_FAILED',
      targetId: alerta.id,
    });
    expect(failed).toHaveLength(1);
    expect(failed[0]).toMatchObject({ outcome: 'FAILURE', actorId: owner.id });

    t.signer.fault = null;
    await apiCancel(ownerSession, alerta.id).expect(201);
  });

  it('el firmante firma el EVENTO pero cae en el ESTADO → 503 y no se guarda ni el evento (atomicidad)', async () => {
    const alerta = await newAlert();
    t.signer.failFrom(2); // 1.ª firma (EVENTO) ok, 2.ª (ESTADO) falla
    await apiCancel(ownerSession, alerta.id).expect(503);
    expect(await eventosOf(alerta.id)).toHaveLength(0);
    const estados = await t.owner.estadoAlerta.findMany({
      where: { alertaId: alerta.id },
    });
    expect(estados.map((e) => e.secuencia)).toEqual([0]);
  });
});
