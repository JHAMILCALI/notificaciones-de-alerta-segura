import { createHash, randomUUID } from 'node:crypto';
import { Client } from 'pg';
import { Role, type PrismaClient } from '@alertasegura/database';
import {
  createDraftRow,
  createTestApp,
  createUser,
  type TestApp,
} from './support/app';

/**
 * Fixture de base de datos: la firma NO es verificable. Aquí solo se prueban permisos, triggers y
 * restricciones SQL; la firma real se comprueba en la publicación (entrega 3).
 */
function signed(doc: object) {
  const payloadCanonico = Buffer.from(JSON.stringify(doc));
  return {
    payloadCanonico,
    hash: createHash('sha256').update(payloadCanonico).digest('hex'),
    firma: 'A'.repeat(86),
    keyId: 'K'.repeat(43),
  };
}

/** Código SQLSTATE (o mensaje) con que PostgreSQL rechaza una sentencia; null si la acepta. */
async function sqlError(
  client: Client,
  sql: string,
  params: unknown[] = [],
): Promise<{ code?: string; message: string } | null> {
  try {
    await client.query(sql, params);
    return null;
  } catch (error) {
    const e = error as { code?: string; message?: string };
    return { code: e.code, message: e.message ?? String(error) };
  }
}

interface Published {
  ownerId: string;
  draftId: string;
  alertaId: string;
  hashAlerta: string;
}

/** Crea (con el propietario) un emisor, su borrador y la alerta publicada a partir de él. */
async function publishedFixture(owner: PrismaClient): Promise<Published> {
  const issuer = await createUser(owner, Role.ISSUER);
  const draft = await createDraftRow(owner, issuer.id);
  const alertaId = randomUUID();
  const doc = signed({ tipo_doc: 'ALERTA', alerta_id: alertaId });
  await owner.alertaPublicada.create({
    data: {
      id: alertaId,
      emisorId: issuer.id,
      draftId: draft.id,
      payloadCanonico: doc.payloadCanonico,
      hashPayload: doc.hash,
      firma: doc.firma,
      keyId: doc.keyId,
      tipo: 'LLUVIAS_INTENSAS',
      departamento: 'LA_PAZ',
      municipio: null,
      severidad: 'NARANJA',
      mensaje: 'Alerta de prueba con texto suficiente.',
      emitidaEn: new Date('2026-10-26T14:00:00Z'),
      expiraEn: new Date('2026-10-27T14:00:00Z'),
    },
  });
  await owner.draft.update({
    where: { id: draft.id },
    data: { status: 'PUBLISHED', alertaId },
  });
  return {
    ownerId: issuer.id,
    draftId: draft.id,
    alertaId,
    hashAlerta: doc.hash,
  };
}

const INSERT_ESTADO = `INSERT INTO "EstadoAlerta"
  ("id","alertaId","secuencia","payloadCanonico","hashPayload","firma","keyId","expiresAt")
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`;

const INSERT_EVENTO = `INSERT INTO "EventoAlerta"
  ("id","alertaId","payloadCanonico","hashEvento","hashAlerta","firma","keyId")
  VALUES ($1,$2,$3,$4,$5,$6,$7)`;

describe('P07: las tablas protegidas rechazan UPDATE, DELETE y TRUNCATE con el rol de la app', () => {
  let t: TestApp;
  let app: Client; // conectado como alertasegura_app
  let ownerSql: Client; // conectado como propietario
  let fx: Published;

  beforeAll(async () => {
    t = await createTestApp();
    app = new Client({ connectionString: process.env.TEST_DATABASE_URL });
    ownerSql = new Client({
      connectionString: process.env.TEST_OWNER_DATABASE_URL,
    });
    await Promise.all([app.connect(), ownerSql.connect()]);

    fx = await publishedFixture(t.owner);
    const evento = signed({ tipo_doc: 'EVENTO', alerta_id: fx.alertaId });
    await ownerSql.query(INSERT_EVENTO, [
      randomUUID(),
      fx.alertaId,
      evento.payloadCanonico,
      evento.hash,
      fx.hashAlerta,
      evento.firma,
      evento.keyId,
    ]);
    const estado = signed({ tipo_doc: 'ESTADO', alerta_id: fx.alertaId });
    await ownerSql.query(INSERT_ESTADO, [
      randomUUID(),
      fx.alertaId,
      0,
      estado.payloadCanonico,
      estado.hash,
      estado.firma,
      estado.keyId,
      new Date('2026-10-26T14:10:00Z'),
    ]);
    await ownerSql.query(
      `INSERT INTO "ClavePublica" ("keyId","jwk","versionRegistro") VALUES ($1,$2,1)`,
      ['K'.repeat(43), { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }],
    );
    await t.owner.auditLog.create({
      data: { action: 'ALERT_PUBLISHED', outcome: 'SUCCESS', metadata: {} },
    });
  });
  afterAll(async () => {
    await Promise.all([app.end(), ownerSql.end()]);
    await t.close();
  });

  const PROTEGIDAS = [
    'AlertaPublicada',
    'EventoAlerta',
    'EstadoAlerta',
    'AuditLog',
    'ClavePublica',
  ] as const;

  const countRows = async (table: string): Promise<number> =>
    Number(
      (
        await ownerSql.query<{ n: string }>(
          `SELECT count(*) AS n FROM "${table}"`,
        )
      ).rows[0]?.n,
    );

  describe.each(PROTEGIDAS)('%s', (table) => {
    it.each([
      ['UPDATE', `UPDATE "${table}" SET "keyId" = "keyId"`],
      ['DELETE', `DELETE FROM "${table}"`],
      ['TRUNCATE', `TRUNCATE TABLE "${table}"`],
    ])('%s → 42501 permission denied', async (_op, sql) => {
      const before = await countRows(table);
      const sentence =
        table === 'AuditLog' ? sql.replaceAll('"keyId"', '"action"') : sql;
      const err = await sqlError(app, sentence);
      expect(err?.code).toBe('42501');
      expect(err?.message).toMatch(/permission denied/i);
      expect(await countRows(table)).toBe(before);
      expect(before).toBeGreaterThan(0); // la prueba no es vacua: hay filas que proteger
    });
  });

  it('el rol de la app SÍ puede leer e insertar donde corresponde (la API funciona con él)', async () => {
    for (const table of [...PROTEGIDAS, 'Draft', 'User', 'Session']) {
      expect(
        await sqlError(app, `SELECT 1 FROM "${table}" LIMIT 1`),
      ).toBeNull();
    }
    expect(
      await sqlError(
        app,
        `UPDATE "Draft" SET "mensaje" = "mensaje" WHERE "id" = $1`,
        [fx.draftId],
      ),
    ).toBeNull();
    expect(await sqlError(app, `DELETE FROM "Session" WHERE false`)).toBeNull();
  });

  it('el rol de la app no puede hacer DDL ni leer los metadatos de migraciones', async () => {
    expect((await sqlError(app, 'CREATE TABLE "intruso" (id int)'))?.code).toBe(
      '42501',
    );
    expect((await sqlError(app, 'DROP TABLE "AlertaPublicada"'))?.code).toBe(
      '42501',
    );
    expect(
      (await sqlError(app, 'ALTER TABLE "AlertaPublicada" DISABLE TRIGGER ALL'))
        ?.code,
    ).toBe('42501');
    expect(
      (
        await sqlError(
          app,
          'DROP TRIGGER "AlertaPublicada_inmutable" ON "AlertaPublicada"',
        )
      )?.code,
    ).toBe('42501');
    expect(
      (await sqlError(app, 'SELECT 1 FROM "_prisma_migrations"'))?.code,
    ).toBe('42501');
  });

  it('el propietario tampoco puede modificar las tres tablas inmutables: lo impide un trigger', async () => {
    for (const table of ['AlertaPublicada', 'EventoAlerta', 'EstadoAlerta']) {
      const before = await countRows(table);
      for (const sql of [
        `UPDATE "${table}" SET "keyId" = "keyId"`,
        `DELETE FROM "${table}"`,
        `TRUNCATE TABLE "${table}"`,
      ]) {
        const err = await sqlError(ownerSql, sql);
        // TRUNCATE de una tabla referenciada por FK lo frena PostgreSQL antes que el trigger.
        expect(err?.message).toMatch(/inmutable|referenced in a foreign key/i);
        expect(err?.code).not.toBe('42501');
      }
      expect(await countRows(table)).toBe(before);
    }
  });

  describe('restricciones de integridad (con el rol de la app)', () => {
    it('un hash que no corresponde a los bytes guardados no entra (CHECK) en alerta, evento ni estado', async () => {
      const other = await createDraftRow(
        t.owner,
        (await createUser(t.owner, Role.ISSUER)).id,
      );
      const doc = signed({ x: 1 });
      const err = await sqlError(
        app,
        `INSERT INTO "AlertaPublicada"
         ("id","emisorId","draftId","payloadCanonico","hashPayload","firma","keyId","tipo","departamento","severidad","mensaje","emitidaEn","expiraEn")
         VALUES ($1,$2,$3,$4,$5,$6,$7,'HELADA','POTOSI','AMARILLA','mensaje de prueba',now(),now() + interval '1 hour')`,
        [
          randomUUID(),
          other.ownerId,
          other.id,
          doc.payloadCanonico,
          'f'.repeat(64),
          doc.firma,
          doc.keyId,
        ],
      );
      expect(err?.code).toBe('23514');

      const estadoErr = await sqlError(app, INSERT_ESTADO, [
        randomUUID(),
        fx.alertaId,
        0,
        doc.payloadCanonico,
        'f'.repeat(64),
        doc.firma,
        doc.keyId,
        new Date(),
      ]);
      expect(estadoErr?.code).toBe('23514');
    });

    it('una sola cancelación por alerta (23505) y el hash_alerta debe ser el de la alerta (23503)', async () => {
      const fresh = await publishedFixture(t.owner);
      const bad = signed({ tipo_doc: 'EVENTO', n: 'hash-ajeno' });
      const wrongHash = await sqlError(app, INSERT_EVENTO, [
        randomUUID(),
        fresh.alertaId,
        bad.payloadCanonico,
        bad.hash,
        'a'.repeat(64),
        bad.firma,
        bad.keyId,
      ]);
      expect(wrongHash?.code).toBe('23503');

      const first = signed({ tipo_doc: 'EVENTO', n: 1 });
      expect(
        await sqlError(app, INSERT_EVENTO, [
          randomUUID(),
          fresh.alertaId,
          first.payloadCanonico,
          first.hash,
          fresh.hashAlerta,
          first.firma,
          first.keyId,
        ]),
      ).toBeNull();
      const second = signed({ tipo_doc: 'EVENTO', n: 2 });
      const dup = await sqlError(app, INSERT_EVENTO, [
        randomUUID(),
        fresh.alertaId,
        second.payloadCanonico,
        second.hash,
        fresh.hashAlerta,
        second.firma,
        second.keyId,
      ]);
      expect(dup?.code).toBe('23505');
    });

    it('un borrador solo se publica una vez (draftId único) y el estado admite regeneraciones con la misma secuencia', async () => {
      const dupAlerta = signed({ tipo_doc: 'ALERTA', n: 'segunda' });
      const err = await sqlError(
        app,
        `INSERT INTO "AlertaPublicada"
         ("id","emisorId","draftId","payloadCanonico","hashPayload","firma","keyId","tipo","departamento","severidad","mensaje","emitidaEn","expiraEn")
         VALUES ($1,$2,$3,$4,$5,$6,$7,'HELADA','POTOSI','AMARILLA','mensaje de prueba',now(),now() + interval '1 hour')`,
        [
          randomUUID(),
          fx.ownerId,
          fx.draftId,
          dupAlerta.payloadCanonico,
          dupAlerta.hash,
          dupAlerta.firma,
          dupAlerta.keyId,
        ],
      );
      expect(err?.code).toBe('23505');

      for (const n of [1, 2]) {
        const estado = signed({ tipo_doc: 'ESTADO', regeneracion: n });
        expect(
          await sqlError(app, INSERT_ESTADO, [
            randomUUID(),
            fx.alertaId,
            0,
            estado.payloadCanonico,
            estado.hash,
            estado.firma,
            estado.keyId,
            new Date(),
          ]),
        ).toBeNull();
      }
      const negative = signed({ tipo_doc: 'ESTADO', secuencia: -1 });
      expect(
        (
          await sqlError(app, INSERT_ESTADO, [
            randomUUID(),
            fx.alertaId,
            -1,
            negative.payloadCanonico,
            negative.hash,
            negative.firma,
            negative.keyId,
            new Date(),
          ])
        )?.code,
      ).toBe('23514');
    });

    it('no se puede borrar un borrador publicado ni su emisor (FK RESTRICT)', async () => {
      const draftDel = await sqlError(
        ownerSql,
        `DELETE FROM "Draft" WHERE "id" = $1`,
        [fx.draftId],
      );
      expect(draftDel?.code).toBe('23503');
      const userDel = await sqlError(
        ownerSql,
        `DELETE FROM "User" WHERE "id" = $1`,
        [fx.ownerId],
      );
      expect(userDel?.code).toBe('23503');
    });
  });
});
