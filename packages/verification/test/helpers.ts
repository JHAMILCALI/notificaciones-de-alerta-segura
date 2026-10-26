import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { bytesToBase64Url, canonicalize, computeKid } from '../src/index.ts';

/** Clave efímera de prueba: se descarta al terminar el proceso y nunca se guarda. */
export interface TestKey {
  privateKey: KeyObject;
  jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  kid: string;
}

export async function makeKey(): Promise<TestKey> {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { kty, crv, x, y } = publicKey.export({ format: 'jwk' });
  const jwk = { kty: kty as 'EC', crv: crv as 'P-256', x: x!, y: y! };
  return { privateKey, jwk, kid: await computeKid(jwk) };
}

export interface Envelope {
  payload_canonico: string;
  hash_payload: string;
  firma: string;
  key_id: string;
}

/** Firma bytes arbitrarios (ECDSA P-256/SHA-256, P1363) y arma el sobre. */
export function envelopeFromBytes(bytes: Buffer, key: TestKey): Envelope {
  return {
    payload_canonico: bytesToBase64Url(bytes),
    hash_payload: createHash('sha256').update(bytes).digest('hex'),
    firma: bytesToBase64Url(sign('sha256', bytes, { key: key.privateKey, dsaEncoding: 'ieee-p1363' })),
    key_id: key.kid,
  };
}

export function signDocument(document: unknown, key: TestKey): Envelope {
  return envelopeFromBytes(Buffer.from(canonicalize(document), 'utf8'), key);
}

export const UUID_A = '3f1c9a52-8d3e-4c1b-9f6a-2b7d5e1a0c11';
export const UUID_B = '9b2e7f10-4a6d-4d58-8c33-5e0f1a7b2d44';
export const UUID_C = 'c4d8a1e6-7b52-4f09-a1d3-6e8b9c0f2a77';

export function alerta(keyId: string) {
  return {
    tipo_doc: 'ALERTA' as const,
    version: 1 as const,
    key_id: keyId,
    alerta_id: UUID_A,
    emisor_id: UUID_B,
    tipo: 'INUNDACION',
    zona: { departamento: 'SANTA_CRUZ', municipio: 'Warnes' },
    severidad: 'NARANJA',
    mensaje: 'Desborde del río Piraí en la zona norte.',
    emitida_en: '2026-10-26T14:05:09Z',
    expira_en: '2026-10-26T20:05:09Z',
  };
}

export function evento(keyId: string) {
  return {
    tipo_doc: 'EVENTO' as const,
    version: 1 as const,
    key_id: keyId,
    evento_id: UUID_C,
    alerta_id: UUID_A,
    hash_alerta: 'a'.repeat(64),
    emisor_id: UUID_B,
    accion: 'CANCELACION' as const,
    emitida_en: '2026-10-26T15:00:00Z',
  };
}

export function estado(keyId: string) {
  return {
    tipo_doc: 'ESTADO' as const,
    version: 1 as const,
    key_id: keyId,
    alerta_id: UUID_A,
    secuencia: 0,
    ultimo_evento_hash: null,
    estado: 'VIGENTE' as const,
    issued_at: '2026-10-26T14:05:10Z',
    expires_at: '2026-10-26T14:15:10Z',
  };
}
