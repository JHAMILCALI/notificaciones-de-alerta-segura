import { Logger } from '@nestjs/common';
import { Role } from '@alertasegura/database';
import {
  AlertaResponseSchema,
  ApiErrorSchema,
  DraftResponseSchema,
  ESTADO_FRESCURA_MAX_SEGUNDOS,
} from '@alertasegura/shared';
import { AuditService } from '../src/modules/audit/audit.service';
import {
  API,
  auditRows,
  createTestApp,
  createUser,
  loggedInBrowser,
  validDraftBody,
  type TestApp,
  type TestUser,
} from './support/app';
import {
  apiCreateDraft,
  apiPublish,
  decodeB64u,
  sha256Hex,
  type Session,
} from './support/alerts';
import { expectValid, verifyWithPackage } from './support/verify';

describe('S2-21: publicación atómica y firmada', () => {
  let t: TestApp;
  let issuer: TestUser;
  let session: Session;

  beforeAll(async () => {
    t = await createTestApp();
    issuer = await createUser(t.prisma, Role.ISSUER);
    session = await loggedInBrowser(t, issuer);
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(() => {
    t.signer.reset();
  });

  const rowsFor = async (draftId: string) => ({
    alertas: await t.owner.alertaPublicada.count({ where: { draftId } }),
    draft: await t.owner.draft.findUniqueOrThrow({ where: { id: draftId } }),
  });

  it('201: guarda los bytes EXACTOS firmados, el hash correcto y una firma que verifica @alertasegura/verification', async () => {
    t.clock.set(new Date('2026-10-26T14:05:09.789Z'));
    const draftId = await apiCreateDraft(session, {
      ...validDraftBody,
      vigenciaHoras: 12,
    });
    const res = await apiPublish(session, draftId).expect(201);
    const { alerta } = AlertaResponseSchema.parse(res.body);

    // 1) La fila guardada contiene los bytes exactos que devolvió el firmante.
    const row = await t.owner.alertaPublicada.findUniqueOrThrow({
      where: { id: alerta.id },
    });
    const bytes = decodeB64u(alerta.alerta.payload_canonico);
    expect(Buffer.compare(Buffer.from(row.payloadCanonico), bytes)).toBe(0);
    expect(row.hashPayload).toBe(sha256Hex(bytes));
    expect(alerta.alerta.hash_payload).toBe(row.hashPayload);
    expect(row).toMatchObject({
      firma: alerta.alerta.firma,
      keyId: t.signer.keyId,
      emisorId: issuer.id,
      draftId,
    });

    // 2) Alerta y estado verifican con el paquete real de verificación.
    const [vAlerta, vEstado] = verifyWithPackage(
      [alerta.alerta, alerta.estado],
      t.signer.publicJwk,
    );
    expectValid(vAlerta);
    expectValid(vEstado);

    // 3) Contenido: D-4 (emitida_en = ahora, expira_en = ahora + vigencia, UTC con segundos).
    expect(vAlerta?.document).toEqual({
      tipo_doc: 'ALERTA',
      version: 1,
      key_id: t.signer.keyId,
      alerta_id: alerta.id,
      emisor_id: issuer.id,
      tipo: validDraftBody.tipo,
      zona: validDraftBody.zona,
      severidad: validDraftBody.severidad,
      mensaje: validDraftBody.mensaje,
      emitida_en: '2026-10-26T14:05:09Z',
      expira_en: '2026-10-27T02:05:09Z',
    });
    expect(vEstado?.document).toEqual({
      tipo_doc: 'ESTADO',
      version: 1,
      key_id: t.signer.keyId,
      alerta_id: alerta.id,
      secuencia: 0,
      ultimo_evento_hash: null,
      estado: 'VIGENTE',
      issued_at: '2026-10-26T14:05:09Z',
      expires_at: '2026-10-26T14:15:09Z',
    });
    expect(ESTADO_FRESCURA_MAX_SEGUNDOS).toBe(600);
    expect(alerta.eventos).toEqual([]);

    // 4) El estado inicial también se guardó (solo INSERT) y el resumen coincide con lo firmado.
    const estados = await t.owner.estadoAlerta.findMany({
      where: { alertaId: alerta.id },
    });
    expect(estados).toHaveLength(1);
    expect(estados[0]).toMatchObject({ secuencia: 0, keyId: t.signer.keyId });
    expect(alerta.resumen).toEqual({
      tipo: validDraftBody.tipo,
      zona: validDraftBody.zona,
      severidad: validDraftBody.severidad,
      mensaje: validDraftBody.mensaje,
      emitida_en: '2026-10-26T14:05:09Z',
      expira_en: '2026-10-27T02:05:09Z',
    });

    // 5) El borrador queda publicado y enlazado; se audita ALERT_PUBLISHED; el firmante vio ALERTA y ESTADO.
    const { draft } = await rowsFor(draftId);
    expect(draft).toMatchObject({ status: 'PUBLISHED', alertaId: alerta.id });
    const audit = await auditRows(t.prisma, {
      action: 'ALERT_PUBLISHED',
      targetId: alerta.id,
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      outcome: 'SUCCESS',
      actorId: issuer.id,
      targetType: 'alerta',
    });
    expect(audit[0]?.metadata).toMatchObject({
      draftId,
      keyId: t.signer.keyId,
      alertaSha256: row.hashPayload,
    });
    expect(t.signer.calls.map((c) => c.tipo_doc)).toEqual(['ALERTA', 'ESTADO']);
    // El firmante recibe el documento SIN key_id: lo añade él.
    expect(t.signer.calls.every((c) => !('key_id' in c))).toBe(true);
  });

  it('publica con municipio null y vigencia de 72 h', async () => {
    t.clock.set(new Date('2026-10-26T00:00:00Z'));
    const draftId = await apiCreateDraft(session, {
      ...validDraftBody,
      zona: { departamento: 'POTOSI', municipio: null },
      tipo: 'HELADA',
      severidad: 'AMARILLA',
      vigenciaHoras: 72,
    });
    const { alerta } = AlertaResponseSchema.parse(
      (await apiPublish(session, draftId).expect(201)).body,
    );
    const [v] = verifyWithPackage([alerta.alerta], t.signer.publicJwk);
    expect(v?.document).toMatchObject({
      zona: { departamento: 'POTOSI', municipio: null },
      expira_en: '2026-10-29T00:00:00Z',
    });
  });

  it('firmante caído → 503 SIGNER_UNAVAILABLE sin filas nuevas; el borrador sigue en DRAFT; se audita PUBLICATION_FAILED; luego se puede reintentar', async () => {
    const draftId = await apiCreateDraft(session);
    const before = await t.owner.estadoAlerta.count();
    t.signer.fault = 'down';

    const res = await apiPublish(session, draftId).expect(503);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 503,
      code: 'SIGNER_UNAVAILABLE',
    });
    expect(JSON.stringify(res.body)).not.toMatch(/socket|pipe|ECONN|ENOENT/i);

    const { alertas, draft } = await rowsFor(draftId);
    expect(alertas).toBe(0);
    expect(draft).toMatchObject({ status: 'DRAFT', alertaId: null });
    expect(await t.owner.estadoAlerta.count()).toBe(before);
    const failed = await auditRows(t.prisma, {
      action: 'PUBLICATION_FAILED',
      targetId: draftId,
    });
    expect(failed).toHaveLength(1);
    expect(failed[0]).toMatchObject({ outcome: 'FAILURE', actorId: issuer.id });
    expect(failed[0]?.metadata).toMatchObject({ reason: 'signer_unavailable' });
    expect(
      await auditRows(t.prisma, {
        action: 'ALERT_PUBLISHED',
        targetId: draftId,
      }),
    ).toHaveLength(0);

    // el firmante vuelve: el mismo borrador se publica sin problema
    t.signer.fault = null;
    await apiPublish(session, draftId).expect(201);
  });

  it('el firmante responde la ALERTA pero cae en la 2.ª firma (ESTADO) → 503 y nada guardado (atomicidad)', async () => {
    const draftId = await apiCreateDraft(session);
    t.signer.failFrom(2);
    await apiPublish(session, draftId).expect(503);
    expect(t.signer.calls).toHaveLength(2);
    const { alertas, draft } = await rowsFor(draftId);
    expect(alertas).toBe(0);
    expect(draft.status).toBe('DRAFT');
  });

  it.each([
    ['un hash que no corresponde a los bytes', 'bad-hash'],
    ['un documento distinto del solicitado', 'other-document'],
  ] as const)(
    'si el firmante devuelve %s → 503 y nada guardado',
    async (_name, fault) => {
      const draftId = await apiCreateDraft(session);
      t.signer.fault = fault;
      const res = await apiPublish(session, draftId).expect(503);
      expect(res.body).toMatchObject({ code: 'SIGNER_UNAVAILABLE' });
      const { alertas, draft } = await rowsFor(draftId);
      expect(alertas).toBe(0);
      expect(draft).toMatchObject({ status: 'DRAFT', alertaId: null });
    },
  );

  it('fallo forzado de la auditoría → ROLLBACK completo: sin alerta, sin estado y borrador en DRAFT', async () => {
    const draftId = await apiCreateDraft(session);
    const logSpy = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const forced = jest
      .spyOn(t.app.get(AuditService), 'recordInTransaction')
      .mockRejectedValueOnce(new Error('auditoría caída (forzado)'));
    const estadosBefore = await t.owner.estadoAlerta.count();

    const res = await apiPublish(session, draftId).expect(500);
    expect(res.body).toMatchObject({ code: 'INTERNAL_ERROR' });
    expect(JSON.stringify(res.body)).not.toContain('forzado');
    expect(forced).toHaveBeenCalledTimes(1);

    const { alertas, draft } = await rowsFor(draftId);
    expect(alertas).toBe(0);
    expect(draft).toMatchObject({ status: 'DRAFT', alertaId: null });
    expect(await t.owner.estadoAlerta.count()).toBe(estadosBefore);
    const failed = await auditRows(t.prisma, {
      action: 'PUBLICATION_FAILED',
      targetId: draftId,
    });
    expect(failed).toHaveLength(1);
    expect(failed[0]?.metadata).toMatchObject({ reason: 'persist_failed' });
    expect(
      await auditRows(t.prisma, {
        action: 'ALERT_PUBLISHED',
        targetType: 'alerta',
      }).then((rows) =>
        rows.filter(
          (r) =>
            r.metadata &&
            (r.metadata as { draftId?: string }).draftId === draftId,
        ),
      ),
    ).toHaveLength(0);

    forced.mockRestore();
    logSpy.mockRestore();
    await apiPublish(session, draftId).expect(201); // y el borrador sigue siendo publicable
  });

  it('publicar dos veces el mismo borrador → 409 CONFLICT, una sola alerta y el firmante no vuelve a firmar', async () => {
    const draftId = await apiCreateDraft(session);
    await apiPublish(session, draftId).expect(201);
    const calls = t.signer.calls.length;

    const res = await apiPublish(session, draftId).expect(409);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 409,
      code: 'CONFLICT',
    });
    expect(t.signer.calls).toHaveLength(calls);
    expect((await rowsFor(draftId)).alertas).toBe(1);
  });

  it('dos publicaciones simultáneas del mismo borrador → una 201 y otra 409; una sola alerta', async () => {
    const draftId = await apiCreateDraft(session);
    const [a, b] = await Promise.all([
      apiPublish(session, draftId),
      apiPublish(session, draftId),
    ]);
    expect([a.status, b.status].sort()).toEqual([201, 409]);
    expect((await rowsFor(draftId)).alertas).toBe(1);
    const stored = await t.owner.draft.findUniqueOrThrow({
      where: { id: draftId },
    });
    expect(stored.status).toBe('PUBLISHED');
  });

  it('el borrador publicado se lee con status PUBLISHED y alertaId; no se puede publicar otro emisor ni sin sesión', async () => {
    const draftId = await apiCreateDraft(session);
    const { alerta } = AlertaResponseSchema.parse(
      (await apiPublish(session, draftId).expect(201)).body,
    );
    const read = DraftResponseSchema.parse(
      (await session.agent.get(`${API}/drafts/${draftId}`).expect(200)).body,
    );
    expect(read.draft).toMatchObject({
      status: 'PUBLISHED',
      alertaId: alerta.id,
    });

    const other = await createUser(t.prisma, Role.ISSUER);
    const otherSession = await loggedInBrowser(t, other);
    await apiPublish(otherSession, draftId).expect(403);
    await t.browser().post(`${API}/drafts/${draftId}/publish`).expect(401);
  });
});
