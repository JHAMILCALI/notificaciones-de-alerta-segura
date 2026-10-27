import { describe, expect, it } from 'vitest';
import { bytesToBase64Url, canonicalize, verifyDocument, verifyManifest, VerificationError } from '../src/index.ts';
import {
  alerta,
  envelopeFromBytes,
  estado,
  evento,
  makeKey,
  signDocument,
  UUID_B,
  type TestKey,
} from './helpers.ts';

async function codeOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof VerificationError) return error.code;
    throw error;
  }
  return 'NO_ERROR';
}

describe('verifyDocument', () => {
  it('acepta ALERTA, EVENTO y ESTADO firmados y devuelve el documento', async () => {
    const key = await makeKey();
    const a = alerta(key.kid);
    const e = evento(key.kid);
    const s = estado(key.kid);
    expect(await verifyDocument({ envelope: signDocument(a, key), jwk: key.jwk, tipoEsperado: 'ALERTA' })).toEqual(a);
    expect(await verifyDocument({ envelope: signDocument(e, key), jwk: key.jwk, tipoEsperado: 'EVENTO' })).toEqual(e);
    expect(await verifyDocument({ envelope: signDocument(s, key), jwk: key.jwk, tipoEsperado: 'ESTADO' })).toEqual(s);
  });

  it('rechaza una JWK con material privado (d)', async () => {
    const key = await makeKey();
    const envelope = signDocument(alerta(key.kid), key);
    const withD = { ...key.jwk, d: 'AAAA' };
    expect(await codeOf(verifyDocument({ envelope, jwk: withD, tipoEsperado: 'ALERTA' }))).toBe('PRIVATE_KEY_REJECTED');
  });

  it('rechaza un tipo_doc distinto del esperado aunque la firma sea válida', async () => {
    const key = await makeKey();
    const envelope = signDocument(evento(key.kid), key);
    expect(await codeOf(verifyDocument({ envelope, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('TIPO_DOC_MISMATCH');
  });

  it('rechaza una firma de otra clave (el key_id del sobre no corresponde a la JWK)', async () => {
    const key = await makeKey();
    const other = await makeKey();
    const envelope = signDocument(alerta(other.kid), other);
    expect(await codeOf(verifyDocument({ envelope, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('KEY_ID_MISMATCH');
  });

  it('rechaza una firma ajena aunque el sobre declare el key_id correcto', async () => {
    const key = await makeKey();
    const other = await makeKey();
    const envelope = { ...signDocument(alerta(key.kid), other), key_id: key.kid };
    expect(await codeOf(verifyDocument({ envelope, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('SIGNATURE_INVALID');
  });

  it('rechaza bytes alterados con el hash sin actualizar', async () => {
    const key = await makeKey();
    const envelope = signDocument(alerta(key.kid), key);
    const other = signDocument({ ...alerta(key.kid), mensaje: 'Otro mensaje distinto del original.' }, key);
    const mixed = { ...envelope, payload_canonico: other.payload_canonico };
    expect(await codeOf(verifyDocument({ envelope: mixed, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('HASH_MISMATCH');
  });

  it('rechaza bytes de un documento con la firma de otro (hash actualizado)', async () => {
    const key = await makeKey();
    const a1 = signDocument(alerta(key.kid), key);
    const a2 = signDocument({ ...alerta(key.kid), mensaje: 'Otro mensaje distinto del original.' }, key);
    const mixed = { ...a2, firma: a1.firma };
    expect(await codeOf(verifyDocument({ envelope: mixed, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('SIGNATURE_INVALID');
  });

  it('rechaza bytes firmados que no están en forma canónica JCS', async () => {
    const key = await makeKey();
    const pretty = Buffer.from(JSON.stringify(alerta(key.kid), null, 2), 'utf8');
    const envelope = envelopeFromBytes(pretty, key);
    expect(await codeOf(verifyDocument({ envelope, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('NOT_CANONICAL');
  });

  it('rechaza un campo extra en el payload firmado', async () => {
    const key = await makeKey();
    const envelope = signDocument({ ...alerta(key.kid), extra: 1 }, key);
    expect(await codeOf(verifyDocument({ envelope, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('INVALID_PAYLOAD');
  });

  it('rechaza un payload cuyo key_id no es el de la clave firmante', async () => {
    const key = await makeKey();
    const other = await makeKey();
    const envelope = signDocument(alerta(other.kid), key);
    expect(await codeOf(verifyDocument({ envelope, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('KEY_ID_MISMATCH');
  });

  it('rechaza un sobre con campos extra o malformado', async () => {
    const key = await makeKey();
    const envelope = signDocument(alerta(key.kid), key);
    expect(await codeOf(verifyDocument({ envelope: { ...envelope, extra: 1 }, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe(
      'INVALID_ENVELOPE',
    );
    expect(await codeOf(verifyDocument({ envelope: null, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('INVALID_ENVELOPE');
  });

  it('rechaza bytes que no son UTF-8 válido', async () => {
    const key = await makeKey();
    const envelope = envelopeFromBytes(Buffer.from([0x7b, 0xff, 0xfe, 0x7d]), key);
    expect(await codeOf(verifyDocument({ envelope, jwk: key.jwk, tipoEsperado: 'ALERTA' }))).toBe('INVALID_PAYLOAD');
  });
});

interface ManifestOptions {
  version?: number;
  issuedAt?: string;
  expiresAt?: string;
  revocadas?: string[];
}

async function makeManifest(root: TestKey, signer: TestKey, options: ManifestOptions = {}) {
  const manifest = {
    tipo_doc: 'MANIFIESTO' as const,
    version: options.version ?? 3,
    root_key_id: root.kid,
    issued_at: options.issuedAt ?? '2026-10-26T12:00:00Z',
    expires_at: options.expiresAt ?? '2026-10-27T12:00:00Z',
    key_id_activo: signer.kid,
    claves: [{ key_id: signer.kid, jwk: signer.jwk }],
    revocadas: options.revocadas ?? [],
    emisores_autorizados: [UUID_B],
  };
  return { manifest, envelope: signDocument(manifest, root) };
}

describe('verifyManifest', () => {
  const ahora = new Date('2026-10-26T13:00:00Z');

  it('acepta un manifiesto vigente firmado por la raíz y lo devuelve', async () => {
    const root = await makeKey();
    const signer = await makeKey();
    const { manifest, envelope } = await makeManifest(root, signer);
    expect(await verifyManifest({ envelope, rootJwk: root.jwk, ahora, versionMinima: 3 })).toEqual(manifest);
  });

  it('rechaza un manifiesto firmado por otra raíz', async () => {
    const root = await makeKey();
    const fake = await makeKey();
    const signer = await makeKey();
    const { envelope } = await makeManifest(fake, signer);
    expect(await codeOf(verifyManifest({ envelope, rootJwk: root.jwk, ahora, versionMinima: 1 }))).toBe('KEY_ID_MISMATCH');
  });

  it('rechaza un manifiesto caducado', async () => {
    const root = await makeKey();
    const signer = await makeKey();
    const { envelope } = await makeManifest(root, signer);
    const later = new Date('2026-10-27T12:00:00Z');
    expect(await codeOf(verifyManifest({ envelope, rootJwk: root.jwk, ahora: later, versionMinima: 1 }))).toBe('MANIFEST_EXPIRED');
  });

  it('rechaza una vigencia mayor de 7 días', async () => {
    const root = await makeKey();
    const signer = await makeKey();
    const { envelope } = await makeManifest(root, signer, { expiresAt: '2026-11-03T12:00:01Z' });
    expect(await codeOf(verifyManifest({ envelope, rootJwk: root.jwk, ahora, versionMinima: 1 }))).toBe('MANIFEST_TOO_LONG');
  });

  it('acepta exactamente 7 días', async () => {
    const root = await makeKey();
    const signer = await makeKey();
    const { envelope } = await makeManifest(root, signer, { expiresAt: '2026-11-02T12:00:00Z' });
    await expect(verifyManifest({ envelope, rootJwk: root.jwk, ahora, versionMinima: 1 })).resolves.toBeDefined();
  });

  it('rechaza una versión inferior a la mínima (rollback)', async () => {
    const root = await makeKey();
    const signer = await makeKey();
    const { envelope } = await makeManifest(root, signer, { version: 2 });
    expect(await codeOf(verifyManifest({ envelope, rootJwk: root.jwk, ahora, versionMinima: 3 }))).toBe(
      'MANIFEST_VERSION_TOO_LOW',
    );
  });

  it('rechaza un manifiesto cuya clave activa está revocada', async () => {
    const root = await makeKey();
    const signer = await makeKey();
    const { envelope } = await makeManifest(root, signer, { revocadas: [signer.kid] });
    expect(await codeOf(verifyManifest({ envelope, rootJwk: root.jwk, ahora, versionMinima: 1 }))).toBe('MANIFEST_INCONSISTENT');
  });

  it('rechaza un key_id de clave que no es la huella de su JWK', async () => {
    const root = await makeKey();
    const signer = await makeKey();
    const impostor = await makeKey();
    const { manifest } = await makeManifest(root, signer);
    const tampered = { ...manifest, claves: [{ key_id: signer.kid, jwk: impostor.jwk }] };
    expect(
      await codeOf(verifyManifest({ envelope: signDocument(tampered, root), rootJwk: root.jwk, ahora, versionMinima: 1 })),
    ).toBe('MANIFEST_INCONSISTENT');
  });

  it('no acepta un documento ALERTA como manifiesto ni una JWK raíz con d', async () => {
    const root = await makeKey();
    const envelope = signDocument(alerta(root.kid), root);
    expect(await codeOf(verifyManifest({ envelope, rootJwk: root.jwk, ahora, versionMinima: 1 }))).toBe('TIPO_DOC_MISMATCH');
    expect(await codeOf(verifyManifest({ envelope, rootJwk: { ...root.jwk, d: 'AAAA' }, ahora, versionMinima: 1 }))).toBe(
      'PRIVATE_KEY_REJECTED',
    );
  });
});

describe('utilidades de prueba', () => {
  it('canonicalize y bytesToBase64Url son coherentes con el sobre', async () => {
    const key = await makeKey();
    const doc = alerta(key.kid);
    const envelope = signDocument(doc, key);
    expect(envelope.payload_canonico).toBe(bytesToBase64Url(Buffer.from(canonicalize(doc), 'utf8')));
  });
});
