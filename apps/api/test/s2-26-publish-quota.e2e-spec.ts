import { createHash, randomUUID } from 'node:crypto';
import { Role } from '@alertasegura/database';
import { ApiErrorSchema } from '@alertasegura/shared';
import {
  auditRows,
  createDraftRow,
  createTestApp,
  createUser,
  loggedInBrowser,
  type TestApp,
} from './support/app';
import {
  apiCancel,
  apiCreateDraft,
  apiPublish,
  apiPublishNew,
  type Session,
} from './support/alerts';

const LIMIT = 3;

describe('S2-26: cuota de publicación por emisor (RATE_PUBLISH_LIMIT) → 429', () => {
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp({
      rateLimits: { publish: { limit: LIMIT, windowSeconds: 3600 } },
    });
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(() => {
    t.signer.reset();
  });

  const newIssuer = async (): Promise<Session & { id: string }> => {
    const user = await createUser(t.prisma, Role.ISSUER);
    return { ...(await loggedInBrowser(t, user)), id: user.id };
  };

  it(`el emisor publica ${LIMIT} alertas; la siguiente → 429 RATE_LIMITED con Retry-After, sin firmar nada y con RATE_LIMITED auditado`, async () => {
    const issuer = await newIssuer();
    for (let i = 0; i < LIMIT; i += 1) await apiPublishNew(issuer);
    const extra = await apiCreateDraft(issuer);
    const calls = t.signer.calls.length;

    const res = await apiPublish(issuer, extra).expect(429);
    expect(ApiErrorSchema.parse(res.body)).toMatchObject({
      statusCode: 429,
      code: 'RATE_LIMITED',
    });
    const retryAfter = Number(res.headers['retry-after']);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(3600);

    // el firmante no se tocó y el borrador sigue siendo un borrador publicable más tarde
    expect(t.signer.calls).toHaveLength(calls);
    const draft = await t.owner.draft.findUniqueOrThrow({
      where: { id: extra },
    });
    expect(draft).toMatchObject({ status: 'DRAFT', alertaId: null });
    expect(
      await t.owner.alertaPublicada.count({ where: { emisorId: issuer.id } }),
    ).toBe(LIMIT);

    const audit = await auditRows(t.prisma, {
      action: 'RATE_LIMITED',
      actorId: issuer.id,
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      outcome: 'DENIED',
      targetId: 'publish-quota',
    });
    expect(audit[0]?.metadata).toMatchObject({
      scope: 'publish-quota',
      limit: LIMIT,
      windowSeconds: 3600,
    });
  });

  it('la cuota es POR emisor: otro emisor sigue publicando', async () => {
    const a = await newIssuer();
    const b = await newIssuer();
    for (let i = 0; i < LIMIT; i += 1) await apiPublishNew(a);
    await apiPublish(a, await apiCreateDraft(a)).expect(429);
    await apiPublishNew(b);
  });

  it('los intentos que fallan (firmante caído, borrador ya publicado) NO consumen la cuota', async () => {
    const issuer = await newIssuer();
    const draftId = await apiCreateDraft(issuer);
    t.signer.fault = 'down';
    for (let i = 0; i < LIMIT + 2; i += 1) {
      await apiPublish(issuer, draftId).expect(503);
    }
    t.signer.fault = null;
    await apiPublish(issuer, draftId).expect(201);
    await apiPublish(issuer, draftId).expect(409);
    // quedan LIMIT - 1 cupos
    for (let i = 0; i < LIMIT - 1; i += 1) await apiPublishNew(issuer);
    await apiPublish(issuer, await apiCreateDraft(issuer)).expect(429);
  });

  it('cancelar no consume ni devuelve cupos', async () => {
    const issuer = await newIssuer();
    const first = await apiPublishNew(issuer);
    await apiCancel(issuer, first.id).expect(201);
    for (let i = 0; i < LIMIT - 1; i += 1) await apiPublishNew(issuer);
    // la cancelada sigue contando dentro de la ventana
    await apiPublish(issuer, await apiCreateDraft(issuer)).expect(429);
  });

  it('las publicaciones fuera de la ventana no cuentan', async () => {
    const issuer = await newIssuer();
    // LIMIT alertas publicadas hace 2 horas (insertadas con el propietario), fuera de la ventana de 1 h
    for (let i = 0; i < LIMIT; i += 1) {
      const draft = await createDraftRow(t.owner, issuer.id);
      const alertaId = randomUUID();
      const bytes = Buffer.from(JSON.stringify({ viejo: i, alertaId }));
      await t.owner.alertaPublicada.create({
        data: {
          id: alertaId,
          emisorId: issuer.id,
          draftId: draft.id,
          payloadCanonico: bytes,
          hashPayload: createHash('sha256').update(bytes).digest('hex'),
          firma: 'A'.repeat(86),
          keyId: 'K'.repeat(43),
          publishedAt: new Date(Date.now() - 2 * 3600_000),
          tipo: 'HELADA',
          departamento: 'POTOSI',
          severidad: 'AMARILLA',
          mensaje: 'Alerta antigua de prueba.',
          emitidaEn: new Date(Date.now() - 2 * 3600_000),
          expiraEn: new Date(Date.now() - 3600_000),
        },
      });
    }
    for (let i = 0; i < LIMIT; i += 1) await apiPublishNew(issuer);
    await apiPublish(issuer, await apiCreateDraft(issuer)).expect(429);
  });

  it(`${LIMIT * 2} publicaciones SIMULTÁNEAS del mismo emisor: exactamente ${LIMIT} entran (bloqueo por emisor) y el resto recibe 429`, async () => {
    const issuer = await newIssuer();
    const drafts = await Promise.all(
      Array.from({ length: LIMIT * 2 }, () => apiCreateDraft(issuer)),
    );
    const responses = await Promise.all(
      drafts.map((id) => apiPublish(issuer, id)),
    );
    const statuses = responses.map((r) => r.status).sort();
    expect(statuses.filter((s) => s === 201)).toHaveLength(LIMIT);
    expect(statuses.filter((s) => s === 429)).toHaveLength(LIMIT);
    expect(
      await t.owner.alertaPublicada.count({ where: { emisorId: issuer.id } }),
    ).toBe(LIMIT);
    // los rechazados no dejan borradores a medias
    const published = await t.owner.draft.count({
      where: { ownerId: issuer.id, status: 'PUBLISHED' },
    });
    expect(published).toBe(LIMIT);
  });
});
