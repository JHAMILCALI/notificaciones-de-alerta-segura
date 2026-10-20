/**
 * Genera tests/fixtures/crypto/p13-vectors.json (P13: interoperabilidad Node <-> Web Crypto).
 *
 * - Par de claves ECDSA P-256 EFÍMERO creado con node:crypto. La clave privada solo vive en
 *   memoria durante esta ejecución: nunca se escribe en disco ni en la salida.
 * - Firma: ECDSA / SHA-256 sobre los bytes UTF-8 del JSON canónico (RFC 8785),
 *   con dsaEncoding 'ieee-p1363' (r||s, 64 bytes) codificado en base64url.
 * - kid: SHA-256 (base64url) de la SPKI DER de la clave pública.
 *
 * Ejecución: pnpm --filter @alertasegura/verification vectors   (Node >= 24, sin dependencias).
 */
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../src/canonicalize.ts';

const here = dirname(fileURLToPath(import.meta.url));
const outFile = resolve(here, '../../../tests/fixtures/crypto/p13-vectors.json');

interface DocumentSpec {
  id: string;
  description: string;
  document: unknown;
}

const documents: DocumentSpec[] = [
  {
    id: 'alert-basic',
    description: 'Alerta mínima con claves en orden no alfabético',
    document: {
      version: 1,
      title: 'Aviso de lluvias intensas',
      severity: 'WARNING',
      issuedAt: '2026-10-19T14:30:00.000Z',
      area: 'Cochabamba',
    },
  },
  {
    id: 'alert-unicode',
    description: 'Unicode: acentos, eñe, euro, emoji (par sustituto) y escapes de control',
    document: {
      mensaje: 'Evacuación inmediata: zona ribereña, niños y mayores primero. 100 € 😀',
      detalle: 'Línea 1\nLínea 2\t(tab) "comillas" \\ barra',
      control: '\u0001\u001f',
      '😀': 'clave con emoji',
      'ñandú': 'clave con eñe',
    },
  },
  {
    id: 'numbers',
    description: 'Números JCS: exponentes, decimales, enteros grandes y menos cero',
    document: {
      numbers: [333333333.33333329, 1e30, 4.5, 0.002, 1e-27, -0, 0.1, 1e21, 123456789012345680000, 5e-324],
      integers: [0, 1, -1, 9007199254740991],
    },
  },
  {
    id: 'nested',
    description: 'Estructuras anidadas, null, booleanos, arreglos y objetos vacíos',
    document: {
      z: { b: [3, 2, 1], a: { y: null, x: true } },
      a: [],
      m: {},
      literals: [null, true, false],
      deep: [[{ k2: 2, k1: 1 }], []],
    },
  },
  {
    id: 'rfc8785-sample',
    description: 'Ejemplo de RFC 8785 §3.2.2',
    document: JSON.parse(
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
        '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"/","literals":[null,true,false]}',
    ),
  },
];

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

const jwkRaw = publicKey.export({ format: 'jwk' });
if (typeof jwkRaw.x !== 'string' || typeof jwkRaw.y !== 'string' || 'd' in jwkRaw) {
  throw new Error('Exportación JWK pública inesperada');
}
const kid = createHash('sha256')
  .update(publicKey.export({ format: 'der', type: 'spki' }))
  .digest('base64url');
const publicKeyJwk = { kty: 'EC', crv: 'P-256', x: jwkRaw.x, y: jwkRaw.y, kid };

const vectors = documents.map(({ id, description, document }) => {
  const canonical = canonicalize(document);
  const bytes = Buffer.from(canonical, 'utf8');
  const signature = sign('sha256', bytes, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  if (signature.length !== 64) throw new Error(`Firma P1363 de longitud inesperada: ${signature.length}`);
  return {
    id,
    description,
    document,
    canonical,
    sha256Hex: createHash('sha256').update(bytes).digest('hex'),
    signature: signature.toString('base64url'),
  };
});

const fixture = {
  $comment:
    'Generado por packages/verification/scripts/generate-p13-vectors.ts con una clave ECDSA P-256 efimera ya descartada. Solo contiene la clave publica y firmas.',
  algorithm: {
    canonicalization: 'JCS RFC 8785',
    signature: 'ECDSA P-256 / SHA-256',
    signatureFormat: 'IEEE P1363 (r||s, 64 bytes) en base64url',
    kid: 'SHA-256 (base64url) de la SPKI DER',
  },
  publicKeyJwk,
  vectors,
};

mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

console.log(`Vectores P13 escritos en ${outFile}`);
console.log(`kid: ${kid}`);
for (const v of vectors) {
  console.log(`  ${v.id}: sha256=${v.sha256Hex} sig=${v.signature.slice(0, 16)}…`);
}
