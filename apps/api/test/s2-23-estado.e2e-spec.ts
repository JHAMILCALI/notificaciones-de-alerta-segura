import { Logger } from '@nestjs/common';
import { Role } from '@alertasegura/database';
import {
  AlertaListResponseSchema,
  AlertaResponseSchema,
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

const T0 = new Date('2026-10-26T14:00:00Z');
const MIN = 60_000;

describe('S2-23: estado firmado (VIGENTE → regeneración → VENCIDA / CANCELADA) con reloj controlado', () => {
  let t: TestApp;
  let session: Session;

  beforeAll(async () => {
    t = await createTestApp();
    session = await loggedInBrowser(t, await createUser(t.prisma, Role.ISSUER));
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(() => {
    t.signer.reset();
    t.clock.set(T0);
  });

  const getAlerta = async (id: string) =>
    AlertaResponseSchema.parse(
      (await t.browser().get(`${API}/alerts/${id}`).expect(200)).body,
    ).alerta;
  const estados = (alertaId: string) =>
    t.owner.estadoAlerta.findMany({
      where: { alertaId },
      orderBy: [{ createdAt: 'asc' }],
    });
  const estadoDoc = (alerta: Awaited<ReturnType<typeof getAlerta>>) => {
    const [v] = verifyWithPackage([alerta.estado], t.signer.publicJwk);
    expectValid(v);
    return v?.document;
  };

  it('al publicar nace VIGENTE, secuencia 0, sin evento, válido 10 minutos', async () => {
    const alerta = await apiPublishNew(session);
    expect(estadoDoc(alerta)).toMatchObject({
      estado: 'VIGENTE',
      secuencia: 0,
      ultimo_evento_hash: null,
      issued_at: '2026-10-26T14:00:00Z',
      expires_at: '2026-10-26T14:10:00Z',
    });
  });

  it('mientras le quedan más de 30 s se sirve el MISMO estado, sin firmar ni guardar otro', async () => {
    const alerta = await apiPublishNew(session);
    const calls = t.signer.calls.length;
    t.clock.set(new Date(T0.getTime() + 9 * MIN)); // quedan 60 s

    const again = await getAlerta(alerta.id);
    expect(again.estado).toEqual(alerta.estado);
    expect(t.signer.calls).toHaveLength(calls);
    expect(await estados(alerta.id)).toHaveLength(1);
  });

  it('con menos de 30 s de vida se regenera: mismo contenido, fechas nuevas (+600 s) y fila nueva (solo INSERT)', async () => {
    const alerta = await apiPublishNew(session);
    t.clock.set(new Date(T0.getTime() + 9 * MIN + 45_000)); // quedan 15 s

    const renewed = await getAlerta(alerta.id);
    expect(renewed.estado.hash_payload).not.toBe(alerta.estado.hash_payload);
    expect(estadoDoc(renewed)).toMatchObject({
      estado: 'VIGENTE',
      secuencia: 0,
      ultimo_evento_hash: null,
      issued_at: '2026-10-26T14:09:45Z',
      expires_at: '2026-10-26T14:19:45Z',
    });
    const rows = await estados(alerta.id);
    expect(rows).toHaveLength(2); // el anterior se conserva
    expect(rows[1]?.expiresAt.toISOString()).toBe('2026-10-26T14:19:45.000Z');
    // la alerta original (bytes y firma) no se toca
    expect(renewed.alerta).toEqual(alerta.alerta);
  });

  it('tras expira_en el estado pasa a VENCIDA (firmado), sin evento y con secuencia 0', async () => {
    const alerta = await apiPublishNew(session, {
      ...validDraftBody,
      vigenciaHoras: 1,
    });
    t.clock.set(new Date(T0.getTime() + 59 * MIN));
    expect(estadoDoc(await getAlerta(alerta.id))).toMatchObject({
      estado: 'VIGENTE',
    });

    t.clock.set(new Date(T0.getTime() + 61 * MIN)); // ya pasó expira_en (15:00)
    const vencida = await getAlerta(alerta.id);
    expect(estadoDoc(vencida)).toMatchObject({
      estado: 'VENCIDA',
      secuencia: 0,
      ultimo_evento_hash: null,
      issued_at: '2026-10-26T15:01:00Z',
    });
    expect(vencida.eventos).toEqual([]);
  });

  it('un estado aún fresco pero que ya no describe la alerta (venció) se regenera sin esperar a su caducidad', async () => {
    const alerta = await apiPublishNew(session, {
      ...validDraftBody,
      vigenciaHoras: 1,
    });
    // a las 14:59:50 se renueva (VIGENTE, válido hasta 15:09:50)
    t.clock.set(new Date(T0.getTime() + 59 * MIN + 50_000));
    await getAlerta(alerta.id);
    // a las 15:00:05 la alerta venció aunque el estado guardado aún tiene ~9 min de vida
    t.clock.set(new Date(T0.getTime() + 60 * MIN + 5_000));
    expect(estadoDoc(await getAlerta(alerta.id))).toMatchObject({
      estado: 'VENCIDA',
      issued_at: '2026-10-26T15:00:05Z',
    });
  });

  it('CANCELADA: secuencia 1 con el hash del evento; se mantiene al regenerarse y aun después de expirar (la cancelación manda)', async () => {
    const alerta = await apiPublishNew(session, {
      ...validDraftBody,
      vigenciaHoras: 1,
    });
    t.clock.set(new Date(T0.getTime() + 5 * MIN));
    const res = await apiCancel(session, alerta.id).expect(201);
    const cancelada = AlertaResponseSchema.parse(res.body).alerta;
    const eventoHash = cancelada.eventos[0]?.hash_payload;
    expect(estadoDoc(cancelada)).toMatchObject({
      estado: 'CANCELADA',
      secuencia: 1,
      ultimo_evento_hash: eventoHash,
    });

    // 10 minutos después: se regenera, sigue CANCELADA con el mismo evento
    t.clock.set(new Date(T0.getTime() + 16 * MIN));
    expect(estadoDoc(await getAlerta(alerta.id))).toMatchObject({
      estado: 'CANCELADA',
      secuencia: 1,
      ultimo_evento_hash: eventoHash,
      issued_at: '2026-10-26T14:16:00Z',
    });

    // pasada la expiración de la alerta, sigue CANCELADA y no VENCIDA
    t.clock.set(new Date(T0.getTime() + 3 * 60 * MIN));
    expect(estadoDoc(await getAlerta(alerta.id))).toMatchObject({
      estado: 'CANCELADA',
      secuencia: 1,
      ultimo_evento_hash: eventoHash,
    });
  });

  it('el último estado manda: mayor secuencia y, a igual secuencia, el más reciente', async () => {
    const alerta = await apiPublishNew(session);
    t.clock.set(new Date(T0.getTime() + 9 * MIN + 45_000));
    await getAlerta(alerta.id); // regenera (secuencia 0, 2.ª fila)
    t.clock.set(new Date(T0.getTime() + 10 * MIN));
    await apiCancel(session, alerta.id).expect(201); // secuencia 1
    // aunque haya filas 0 posteriores en el tiempo, la secuencia 1 es la vigente
    t.clock.set(new Date(T0.getTime() + 11 * MIN));
    const latest = estadoDoc(await getAlerta(alerta.id));
    expect(latest).toMatchObject({ estado: 'CANCELADA', secuencia: 1 });
    const rows = await estados(alerta.id);
    expect(rows.map((r) => r.secuencia)).toEqual([0, 0, 1]);
  });

  it('si hay que regenerar y el firmante está caído se sirve el último estado guardado (caducado) en vez de fallar, y no se escribe nada', async () => {
    const warn = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => undefined);
    const alerta = await apiPublishNew(session);
    t.clock.set(new Date(T0.getTime() + 30 * MIN)); // estado caducado
    t.signer.fault = 'down';

    const stale = await getAlerta(alerta.id);
    expect(stale.estado).toEqual(alerta.estado); // el auténtico, ya vencido: el verificador decide por expires_at
    expect(await estados(alerta.id)).toHaveLength(1);

    t.signer.fault = null;
    const renewed = await getAlerta(alerta.id);
    expect(renewed.estado.hash_payload).not.toBe(alerta.estado.hash_payload);
    warn.mockRestore();
  });

  it('GET /alerts también entrega estados frescos', async () => {
    const alerta = await apiPublishNew(session);
    t.clock.set(new Date(T0.getTime() + 9 * MIN + 50_000));
    const list = AlertaListResponseSchema.parse(
      (await t.browser().get(`${API}/alerts?limit=100`).expect(200)).body,
    );
    const mine = list.alertas.find((a) => a.id === alerta.id);
    expect(mine?.estado.hash_payload).not.toBe(alerta.estado.hash_payload);
    const [v] = verifyWithPackage([mine!.estado], t.signer.publicJwk);
    expectValid(v);
  });
});
