import {
  createHash,
  generateKeyPairSync,
  sign as ecdsaSign,
} from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  ManifiestoDocumentoSchema,
  type PublicJwk,
  type SignedEnvelope,
} from '@alertasegura/shared';
import { API, createTestApp, type TestApp } from './support/app';
import { jcs } from './support/fake-signer';

interface TestKey {
  keyId: string;
  jwk: PublicJwk;
}

function newKey(): TestKey & {
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
} {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const jwk = publicKey.export({ format: 'jwk' });
  return {
    privateKey,
    jwk: { kty: 'EC', crv: 'P-256', x: jwk.x ?? '', y: jwk.y ?? '' },
    keyId: createHash('sha256')
      .update(publicKey.export({ type: 'spki', format: 'der' }))
      .digest('base64url'),
  };
}

const root = newKey();

/** Manifiesto firmado por una raíz de prueba, con la misma forma que emite la CLI de confianza. */
function manifestEnvelope(
  version: number,
  claves: Array<{ key_id: string; jwk: PublicJwk }>,
  mutate: (doc: Record<string, unknown>) => void = () => undefined,
): SignedEnvelope {
  const doc: Record<string, unknown> = ManifiestoDocumentoSchema.parse({
    tipo_doc: 'MANIFIESTO',
    version,
    root_key_id: root.keyId,
    issued_at: '2026-10-26T12:00:00Z',
    expires_at: '2026-10-27T12:00:00Z',
    key_id_activo: claves[0]?.key_id,
    claves,
    revocadas: [],
    emisores_autorizados: [],
  });
  mutate(doc);
  const bytes = Buffer.from(jcs(doc), 'utf8');
  return {
    payload_canonico: bytes.toString('base64url'),
    hash_payload: createHash('sha256').update(bytes).digest('hex'),
    firma: ecdsaSign('sha256', bytes, {
      key: root.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url'),
    key_id: root.keyId,
  };
}

describe('S2-25: inventario de claves públicas a partir del manifiesto (al arrancar; solo INSERT)', () => {
  let dir: string;
  let file: string;
  const apps: TestApp[] = [];

  /** Arrancar la API = arrancar con el manifiesto que haya en `file`. */
  const boot = async (): Promise<TestApp> => {
    const app = await createTestApp({ trustManifestFile: file });
    apps.push(app);
    return app;
  };
  const rowsOf = (t: TestApp, keyIds: string[]) =>
    t.owner.clavePublica.findMany({
      where: { keyId: { in: keyIds } },
      orderBy: { keyId: 'asc' },
    });

  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'as-inventory-'));
    file = path.join(dir, 'manifest.json');
  });
  afterAll(async () => {
    await Promise.all(apps.map((a) => a.close()));
    rmSync(dir, { recursive: true, force: true });
  });

  it('al arrancar registra las claves del manifiesto con su JWK y la versión en que se vieron', async () => {
    const [a, b] = [newKey(), newKey()];
    writeFileSync(
      file,
      JSON.stringify(
        manifestEnvelope(1, [
          { key_id: a.keyId, jwk: a.jwk },
          { key_id: b.keyId, jwk: b.jwk },
        ]),
      ),
    );
    const t = await boot();

    const rows = await rowsOf(t, [a.keyId, b.keyId]);
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.versionRegistro).toBe(1);
      expect(row.creadoEn).toBeInstanceOf(Date);
    }
    expect(rows.find((r) => r.keyId === a.keyId)?.jwk).toEqual(a.jwk);
    // el JWK guardado es público: nunca lleva material privado
    expect(JSON.stringify(rows)).not.toMatch(/"d"/);
  });

  it('un manifiesto nuevo solo añade las claves nuevas: las ya registradas no se tocan (versionRegistro intacta)', async () => {
    const [a, b, c] = [newKey(), newKey(), newKey()];
    writeFileSync(
      file,
      JSON.stringify(
        manifestEnvelope(1, [
          { key_id: a.keyId, jwk: a.jwk },
          { key_id: b.keyId, jwk: b.jwk },
        ]),
      ),
    );
    const first = await boot();
    const before = await rowsOf(first, [a.keyId, b.keyId]);

    writeFileSync(
      file,
      JSON.stringify(
        manifestEnvelope(2, [
          { key_id: a.keyId, jwk: a.jwk },
          { key_id: b.keyId, jwk: b.jwk },
          { key_id: c.keyId, jwk: c.jwk },
        ]),
      ),
    );
    const second = await boot(); // otro arranque con el manifiesto v2

    const rows = await rowsOf(second, [a.keyId, b.keyId, c.keyId]);
    expect(rows).toHaveLength(3);
    expect(rows.find((r) => r.keyId === c.keyId)?.versionRegistro).toBe(2);
    expect(rows.filter((r) => r.keyId !== c.keyId)).toEqual(before); // idénticas, byte a byte
  });

  it('una clave cuyo key_id no corresponde a su JWK se descarta; las demás se registran', async () => {
    const [good, bad, other] = [newKey(), newKey(), newKey()];
    writeFileSync(
      file,
      JSON.stringify(
        manifestEnvelope(1, [
          { key_id: good.keyId, jwk: good.jwk },
          { key_id: bad.keyId, jwk: other.jwk }, // key_id de una, JWK de otra
        ]),
      ),
    );
    const t = await boot();
    expect(
      (await rowsOf(t, [good.keyId, bad.keyId, other.keyId])).map(
        (r) => r.keyId,
      ),
    ).toEqual([good.keyId]);
  });

  it('un manifiesto con hash_payload que no corresponde a sus bytes no registra nada, y la API arranca igual', async () => {
    const k = newKey();
    const envelope = manifestEnvelope(1, [{ key_id: k.keyId, jwk: k.jwk }]);
    writeFileSync(
      file,
      JSON.stringify({ ...envelope, hash_payload: 'f'.repeat(64) }),
    );
    const t = await boot();
    expect(await rowsOf(t, [k.keyId])).toHaveLength(0);
    await t.browser().get(`${API}/health`).expect(200);
  });

  it.each([['archivo inexistente', () => path.join(dir, 'no-existe.json')]])(
    '%s → la API arranca sin registrar nada',
    async (_name, makePath) => {
      const t = await createTestApp({ trustManifestFile: makePath() });
      apps.push(t);
      await t.browser().get(`${API}/health`).expect(200);
    },
  );

  it('sin TRUST_MANIFEST_FILE configurado no hay inventario y la API arranca', async () => {
    const before = await (await boot()).owner.clavePublica.count();
    const t = await createTestApp({ trustManifestFile: null });
    apps.push(t);
    await t.browser().get(`${API}/health`).expect(200);
    expect(await t.owner.clavePublica.count()).toBe(before);
  });

  it('la tabla no es una autoridad: añadir una fila a mano no cambia lo que sirve /trust/manifest', async () => {
    const k = newKey();
    const envelope = manifestEnvelope(1, [{ key_id: k.keyId, jwk: k.jwk }]);
    writeFileSync(file, JSON.stringify(envelope));
    const t = await boot();
    const intruder = newKey();
    await t.owner.clavePublica.create({
      data: {
        keyId: intruder.keyId,
        jwk: { ...intruder.jwk },
        versionRegistro: 99,
      },
    });
    const served = (await t.browser().get(`${API}/trust/manifest`).expect(200))
      .body as {
      manifiesto: SignedEnvelope;
    };
    expect(served.manifiesto).toEqual(envelope);
    expect(JSON.stringify(served)).not.toContain(intruder.keyId);
  });
});
