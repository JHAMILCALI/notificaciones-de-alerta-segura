import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { computeKid, verifyCancelacion, verifyDocument, VerificationError } from '../src/index.ts';
import { alerta, evento, makeKey, signDocument } from './helpers.ts';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, '../../../tests/fixtures/crypto');

type Expected = { valid: true } | { valid: false; code: string };
interface Envelope {
  payload_canonico: string;
  hash_payload: string;
  firma: string;
  key_id: string;
}

function load<T>(name: string): { raw: string; data: T } {
  const raw = readFileSync(resolve(fixturesDir, name), 'utf8');
  return { raw, data: JSON.parse(raw) as T };
}

async function outcome(promise: Promise<unknown>): Promise<Expected> {
  try {
    await promise;
    return { valid: true };
  } catch (error) {
    if (error instanceof VerificationError) return { valid: false, code: error.code };
    throw error;
  }
}

describe('P16: separación de tipos de documento (vectores versionados)', () => {
  const { raw, data } = load<{
    publicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
    keyId: string;
    vectors: Array<{ id: string; description: string; tipoEsperado: 'ALERTA' | 'EVENTO' | 'ESTADO'; envelope: Envelope; expected: Expected }>;
  }>('p16-vectors.json');

  it('el fixture contiene solo material público y su key_id es la huella de la clave', async () => {
    expect(data.publicKeyJwk).not.toHaveProperty('d');
    expect(raw).not.toMatch(/"d"\s*:/);
    expect(raw).not.toMatch(/PRIVATE KEY/);
    expect(await computeKid(data.publicKeyJwk)).toBe(data.keyId);
  });

  it('cubre los casos de la ficha: tipo cruzado, tipo_doc cambiado y bytes con la firma de otro', () => {
    const ids = data.vectors.map((v) => v.id);
    for (const required of [
      'evento-como-alerta',
      'alerta-como-evento',
      'estado-como-evento',
      'tipo-doc-cambiado',
      'bytes-de-un-documento-con-firma-de-otro',
    ]) {
      expect(ids).toContain(required);
    }
    expect(data.vectors.filter((v) => v.expected.valid)).toHaveLength(3);
  });

  for (const vector of data.vectors) {
    it(`${vector.id}: ${vector.description}`, async () => {
      const result = await outcome(
        verifyDocument({ envelope: vector.envelope, jwk: data.publicKeyJwk, tipoEsperado: vector.tipoEsperado }),
      );
      expect(result).toEqual(vector.expected);
    });
  }

  it('los rechazos por tipo se distinguen de los rechazos por firma', () => {
    const codes = new Set(data.vectors.flatMap((v) => (v.expected.valid ? [] : [v.expected.code])));
    expect(codes.has('TIPO_DOC_MISMATCH')).toBe(true);
    expect(codes.has('SIGNATURE_INVALID')).toBe(true);
  });
});

describe('P06: cancelaciones falsificadas (vectores versionados)', () => {
  const { raw, data } = load<{
    publicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
    keyId: string;
    alerta: Envelope;
    vectors: Array<{ id: string; description: string; evento: Envelope; expected: Expected }>;
  }>('p06-vectors.json');

  it('el fixture contiene solo material público', async () => {
    expect(raw).not.toMatch(/"d"\s*:/);
    expect(raw).not.toMatch(/PRIVATE KEY/);
    expect(await computeKid(data.publicKeyJwk)).toBe(data.keyId);
  });

  it('cubre otra clave, hash_alerta que no coincide y firma de ALERTA', () => {
    const ids = data.vectors.map((v) => v.id);
    expect(ids).toContain('evento-otra-clave');
    expect(ids).toContain('hash-alerta-no-coincide');
    expect(ids).toContain('firma-de-alerta-como-evento');
  });

  for (const vector of data.vectors) {
    it(`${vector.id}: ${vector.description}`, async () => {
      const result = await outcome(verifyCancelacion(data.alerta, vector.evento, data.publicKeyJwk));
      expect(result).toEqual(vector.expected);
    });
  }
});

describe('verifyCancelacion', () => {
  it('devuelve alerta y evento cuando la cancelación es legítima', async () => {
    const key = await makeKey();
    const a = signDocument(alerta(key.kid), key);
    const e = signDocument(evento(key.kid), key);
    const withHash = signDocument({ ...evento(key.kid), hash_alerta: a.hash_payload }, key);
    expect(await outcome(verifyCancelacion(a, e, key.jwk))).toEqual({ valid: false, code: 'CANCELACION_HASH_MISMATCH' });
    const ok = await verifyCancelacion(a, withHash, key.jwk);
    expect(ok.alerta.alerta_id).toBe(ok.evento.alerta_id);
    expect(ok.evento.hash_alerta).toBe(a.hash_payload);
  });

  it('rechaza una JWK con material privado', async () => {
    const key = await makeKey();
    const a = signDocument(alerta(key.kid), key);
    const e = signDocument({ ...evento(key.kid), hash_alerta: a.hash_payload }, key);
    expect(await outcome(verifyCancelacion(a, e, { ...key.jwk, d: 'AAAA' }))).toEqual({
      valid: false,
      code: 'PRIVATE_KEY_REJECTED',
    });
  });

  it('el hash se compara con los bytes exactos de la alerta firmada, no con campos reconstruidos', async () => {
    const key = await makeKey();
    const a = signDocument(alerta(key.kid), key);
    // Misma alerta con otro mensaje: otros bytes, otro hash, aunque el alerta_id sea el mismo.
    const forgedAlerta = signDocument({ ...alerta(key.kid), mensaje: 'Mensaje distinto del original firmado.' }, key);
    const e = signDocument({ ...evento(key.kid), hash_alerta: a.hash_payload }, key);
    expect(await outcome(verifyCancelacion(forgedAlerta, e, key.jwk))).toEqual({
      valid: false,
      code: 'CANCELACION_HASH_MISMATCH',
    });
  });
});
