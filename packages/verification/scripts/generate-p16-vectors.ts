/**
 * Genera tests/fixtures/crypto/p16-vectors.json (P16: separación de tipos de documento) y
 * tests/fixtures/crypto/p06-vectors.json (P06: cancelaciones falsificadas).
 *
 * - Pares de claves ECDSA P-256 EFÍMEROS creados con node:crypto: la clave del firmante legítimo y la
 *   de un atacante. Las privadas solo viven en memoria durante esta ejecución: nunca se escriben ni
 *   se imprimen. En los archivos solo quedan claves públicas, sobres firmados y el resultado esperado.
 * - Los sobres siguen el contrato de packages/shared (SignedEnvelope): bytes JCS en base64url, SHA-256 en
 *   hexadecimal, firma IEEE P1363 en base64url y key_id = SHA-256 de la SPKI.
 *
 * Ejecución: pnpm --filter @alertasegura/verification vectors:p16   (Node >= 24).
 */
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bytesToBase64Url } from '../src/base64url.ts';
import { canonicalize } from '../src/canonicalize.ts';
import { computeKid } from '../src/verify.ts';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, '../../../tests/fixtures/crypto');

interface Signer {
  privateKey: KeyObject;
  jwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string };
  keyId: string;
}

async function newSigner(): Promise<Signer> {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { kty, crv, x, y } = publicKey.export({ format: 'jwk' });
  const jwk = { kty: kty as 'EC', crv: crv as 'P-256', x: x!, y: y! };
  return { privateKey, jwk, keyId: await computeKid(jwk) };
}

interface Envelope {
  payload_canonico: string;
  hash_payload: string;
  firma: string;
  key_id: string;
}

function signBytes(signer: Signer, bytes: Buffer): Envelope {
  return {
    payload_canonico: bytesToBase64Url(bytes),
    hash_payload: createHash('sha256').update(bytes).digest('hex'),
    firma: bytesToBase64Url(sign('sha256', bytes, { key: signer.privateKey, dsaEncoding: 'ieee-p1363' })),
    key_id: signer.keyId,
  };
}

const signDoc = (signer: Signer, doc: unknown): Envelope => signBytes(signer, Buffer.from(canonicalize(doc), 'utf8'));

const EMISOR = '9b2e7f10-4a6d-4d58-8c33-5e0f1a7b2d44';
const OTRO_EMISOR = '5d7a3c92-1e48-4b0f-a6c5-3f9e8d2b7a10';
const ALERTA_ID = '3f1c9a52-8d3e-4c1b-9f6a-2b7d5e1a0c11';
const OTRA_ALERTA_ID = '7e4b1d36-9a02-4c58-b1f7-0d6c3a5e8b92';
const EVENTO_ID = 'c4d8a1e6-7b52-4f09-a1d3-6e8b9c0f2a77';

const alerta = (keyId: string, overrides: Record<string, unknown> = {}) => ({
  tipo_doc: 'ALERTA',
  version: 1,
  key_id: keyId,
  alerta_id: ALERTA_ID,
  emisor_id: EMISOR,
  tipo: 'INUNDACION',
  zona: { departamento: 'SANTA_CRUZ', municipio: 'Warnes' },
  severidad: 'NARANJA',
  mensaje: 'Desborde del río Piraí en la zona norte: evacuar hacia terreno alto.',
  emitida_en: '2026-10-26T14:05:09Z',
  expira_en: '2026-10-26T20:05:09Z',
  ...overrides,
});

const evento = (keyId: string, hashAlerta: string, overrides: Record<string, unknown> = {}) => ({
  tipo_doc: 'EVENTO',
  version: 1,
  key_id: keyId,
  evento_id: EVENTO_ID,
  alerta_id: ALERTA_ID,
  hash_alerta: hashAlerta,
  emisor_id: EMISOR,
  accion: 'CANCELACION',
  emitida_en: '2026-10-26T15:00:00Z',
  ...overrides,
});

const estado = (keyId: string) => ({
  tipo_doc: 'ESTADO',
  version: 1,
  key_id: keyId,
  alerta_id: ALERTA_ID,
  secuencia: 0,
  ultimo_evento_hash: null,
  estado: 'VIGENTE',
  issued_at: '2026-10-26T14:05:10Z',
  expires_at: '2026-10-26T14:15:10Z',
});

type Tipo = 'ALERTA' | 'EVENTO' | 'ESTADO';
interface P16Vector {
  id: string;
  description: string;
  tipoEsperado: Tipo;
  envelope: Envelope;
  expected: { valid: true } | { valid: false; code: string };
}

/** Altera los bytes firmados y recalcula el hash, pero conserva la firma original. */
function tamper(original: Envelope, mutate: (doc: Record<string, unknown>) => void): Envelope {
  const doc = JSON.parse(Buffer.from(original.payload_canonico, 'base64url').toString('utf8')) as Record<string, unknown>;
  mutate(doc);
  const bytes = Buffer.from(canonicalize(doc), 'utf8');
  return {
    ...original,
    payload_canonico: bytesToBase64Url(bytes),
    hash_payload: createHash('sha256').update(bytes).digest('hex'),
  };
}

async function generateP16(): Promise<void> {
  const signer = await newSigner();
  const a = signDoc(signer, alerta(signer.keyId));
  const e = signDoc(signer, evento(signer.keyId, a.hash_payload));
  const s = signDoc(signer, estado(signer.keyId));
  const otraAlerta = signDoc(signer, alerta(signer.keyId, { alerta_id: OTRA_ALERTA_ID, mensaje: 'Otro mensaje de alerta distinto.' }));

  const vectors: P16Vector[] = [
    { id: 'ok-alerta', description: 'Control: ALERTA legítima verificada como ALERTA', tipoEsperado: 'ALERTA', envelope: a, expected: { valid: true } },
    { id: 'ok-evento', description: 'Control: EVENTO legítimo verificado como EVENTO', tipoEsperado: 'EVENTO', envelope: e, expected: { valid: true } },
    { id: 'ok-estado', description: 'Control: ESTADO legítimo verificado como ESTADO', tipoEsperado: 'ESTADO', envelope: s, expected: { valid: true } },
    {
      id: 'evento-como-alerta',
      description: 'La firma válida de un EVENTO presentada como ALERTA',
      tipoEsperado: 'ALERTA',
      envelope: e,
      expected: { valid: false, code: 'TIPO_DOC_MISMATCH' },
    },
    {
      id: 'alerta-como-evento',
      description: 'La firma válida de una ALERTA presentada como EVENTO',
      tipoEsperado: 'EVENTO',
      envelope: a,
      expected: { valid: false, code: 'TIPO_DOC_MISMATCH' },
    },
    {
      id: 'estado-como-evento',
      description: 'La firma válida de un ESTADO presentada como EVENTO',
      tipoEsperado: 'EVENTO',
      envelope: s,
      expected: { valid: false, code: 'TIPO_DOC_MISMATCH' },
    },
    {
      id: 'estado-como-alerta',
      description: 'La firma válida de un ESTADO presentada como ALERTA',
      tipoEsperado: 'ALERTA',
      envelope: s,
      expected: { valid: false, code: 'TIPO_DOC_MISMATCH' },
    },
    {
      id: 'tipo-doc-cambiado',
      description: 'ALERTA firmada con tipo_doc cambiado a EVENTO después de firmar (hash recalculado, firma original)',
      tipoEsperado: 'EVENTO',
      envelope: tamper(a, (doc) => {
        doc.tipo_doc = 'EVENTO';
      }),
      expected: { valid: false, code: 'SIGNATURE_INVALID' },
    },
    {
      id: 'tipo-doc-cambiado-sin-recalcular-hash',
      description: 'ALERTA con tipo_doc cambiado y el hash_payload original',
      tipoEsperado: 'EVENTO',
      envelope: { ...a, payload_canonico: tamper(a, (doc) => { doc.tipo_doc = 'EVENTO'; }).payload_canonico },
      expected: { valid: false, code: 'HASH_MISMATCH' },
    },
    {
      id: 'bytes-de-un-documento-con-firma-de-otro',
      description: 'Bytes y hash de una ALERTA con la firma de otra ALERTA del mismo firmante',
      tipoEsperado: 'ALERTA',
      envelope: { ...a, firma: otraAlerta.firma },
      expected: { valid: false, code: 'SIGNATURE_INVALID' },
    },
    {
      id: 'bytes-de-alerta-con-firma-de-evento',
      description: 'Bytes y hash de una ALERTA con la firma de un EVENTO',
      tipoEsperado: 'ALERTA',
      envelope: { ...a, firma: e.firma },
      expected: { valid: false, code: 'SIGNATURE_INVALID' },
    },
  ];

  write('p16-vectors.json', {
    $comment:
      'Generado por packages/verification/scripts/generate-p16-vectors.ts con una clave ECDSA P-256 efimera ya descartada. Solo contiene la clave publica, sobres firmados y el resultado esperado de verifyDocument.',
    publicKeyJwk: signer.jwk,
    keyId: signer.keyId,
    vectors,
  });
}

interface P06Vector {
  id: string;
  description: string;
  evento: Envelope;
  expected: { valid: true } | { valid: false; code: string };
}

async function generateP06(): Promise<void> {
  const signer = await newSigner();
  const attacker = await newSigner();
  const a = signDoc(signer, alerta(signer.keyId));
  const otraAlerta = signDoc(signer, alerta(signer.keyId, { alerta_id: OTRA_ALERTA_ID, mensaje: 'Otro mensaje de alerta distinto.' }));

  const vectors: P06Vector[] = [
    {
      id: 'ok-cancelacion',
      description: 'Control: cancelación legítima de la alerta',
      evento: signDoc(signer, evento(signer.keyId, a.hash_payload)),
      expected: { valid: true },
    },
    {
      id: 'evento-otra-clave',
      description: 'EVENTO bien formado firmado con una clave del atacante',
      evento: signDoc(attacker, evento(attacker.keyId, a.hash_payload)),
      expected: { valid: false, code: 'KEY_ID_MISMATCH' },
    },
    {
      id: 'evento-otra-clave-con-key-id-legitimo',
      description: 'EVENTO firmado por el atacante pero declarando el key_id del firmante legítimo',
      evento: { ...signDoc(attacker, evento(signer.keyId, a.hash_payload)), key_id: signer.keyId },
      expected: { valid: false, code: 'SIGNATURE_INVALID' },
    },
    {
      id: 'hash-alerta-no-coincide',
      description: 'EVENTO legítimo cuyo hash_alerta corresponde a otra alerta',
      evento: signDoc(signer, evento(signer.keyId, otraAlerta.hash_payload)),
      expected: { valid: false, code: 'CANCELACION_HASH_MISMATCH' },
    },
    {
      id: 'hash-alerta-inventado',
      description: 'EVENTO legítimo con un hash_alerta que no es de ninguna alerta',
      evento: signDoc(signer, evento(signer.keyId, 'f'.repeat(64))),
      expected: { valid: false, code: 'CANCELACION_HASH_MISMATCH' },
    },
    {
      id: 'firma-de-alerta-como-evento',
      description: 'Se presenta como evento la firma válida de otra ALERTA',
      evento: otraAlerta,
      expected: { valid: false, code: 'TIPO_DOC_MISMATCH' },
    },
    {
      id: 'evento-de-otra-alerta',
      description: 'EVENTO legítimo para otra alerta_id pero con el hash de esta alerta',
      evento: signDoc(signer, evento(signer.keyId, a.hash_payload, { alerta_id: OTRA_ALERTA_ID })),
      expected: { valid: false, code: 'CANCELACION_ALERTA_MISMATCH' },
    },
    {
      id: 'evento-de-otro-emisor',
      description: 'EVENTO legítimo emitido por un emisor distinto del de la alerta',
      evento: signDoc(signer, evento(signer.keyId, a.hash_payload, { emisor_id: OTRO_EMISOR })),
      expected: { valid: false, code: 'CANCELACION_EMISOR_MISMATCH' },
    },
    {
      id: 'evento-con-hash-alterado-tras-firmar',
      description: 'EVENTO con hash_alerta cambiado después de firmar (hash_payload recalculado, firma original)',
      evento: tamper(signDoc(signer, evento(signer.keyId, a.hash_payload)), (doc) => {
        doc.hash_alerta = 'f'.repeat(64);
      }),
      expected: { valid: false, code: 'SIGNATURE_INVALID' },
    },
  ];

  write('p06-vectors.json', {
    $comment:
      'Generado por packages/verification/scripts/generate-p16-vectors.ts con claves ECDSA P-256 efimeras ya descartadas (firmante y atacante). Solo contiene claves publicas, sobres firmados y el resultado esperado de verifyCancelacion.',
    publicKeyJwk: signer.jwk,
    keyId: signer.keyId,
    alerta: a,
    vectors,
  });
}

function write(name: string, content: unknown): void {
  mkdirSync(outDir, { recursive: true });
  const text = `${JSON.stringify(content, null, 2)}\n`;
  // Red de seguridad: ningún material privado puede llegar al archivo.
  if (/"d"\s*:|PRIVATE KEY/.test(text)) throw new Error(`El vector ${name} contiene material privado`);
  writeFileSync(resolve(outDir, name), text);
  console.log(`Escrito ${name}`);
}

await generateP16();
await generateP06();
