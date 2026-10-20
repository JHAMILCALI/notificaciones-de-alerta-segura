import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalize,
  CanonicalizationError,
  computeKid,
  importPublicKeyJwk,
  sha256Hex,
  utf8,
  verifyCanonicalSignature,
  VerificationError,
} from '../src/index.ts';

interface Vector {
  id: string;
  description: string;
  document: unknown;
  canonical: string;
  sha256Hex: string;
  signature: string;
}
interface Fixture {
  publicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string; kid: string };
  vectors: Vector[];
}

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../../../tests/fixtures/crypto/p13-vectors.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as Fixture;

/** Copia profunda del documento para poder alterarlo sin tocar el vector. */
function clone<T>(value: T): T {
  return structuredClone(value);
}

function flipBit(signatureB64u: string, bitIndex: number): string {
  const bytes = base64UrlToBytes(signatureB64u);
  bytes[Math.floor(bitIndex / 8)]! ^= 1 << bitIndex % 8;
  return bytesToBase64Url(bytes);
}

describe('P13 vectores generados en Node verificados con Web Crypto', () => {
  it('el fixture contiene solo material público', () => {
    const raw = readFileSync(fixturePath, 'utf8');
    expect(fixture.vectors.length).toBeGreaterThanOrEqual(4);
    expect(fixture.publicKeyJwk).not.toHaveProperty('d');
    expect(raw).not.toMatch(/"d"\s*:/);
    expect(raw).not.toMatch(/PRIVATE KEY/);
  });

  it('el kid coincide con el SHA-256 de la SPKI DER (calculado con node:crypto y con Web Crypto)', async () => {
    const der = createPublicKey({ key: fixture.publicKeyJwk, format: 'jwk' }).export({ format: 'der', type: 'spki' });
    expect(createHash('sha256').update(der).digest('base64url')).toBe(fixture.publicKeyJwk.kid);
    expect(await computeKid(fixture.publicKeyJwk)).toBe(fixture.publicKeyJwk.kid);
  });

  describe.each(fixture.vectors)('vector $id', (vector) => {
    it('la forma canónica se reproduce con canonicalize()', () => {
      expect(canonicalize(vector.document)).toBe(vector.canonical);
    });

    it('el SHA-256 se reproduce con Web Crypto', async () => {
      expect(await sha256Hex(vector.canonical)).toBe(vector.sha256Hex);
    });

    it('la firma tiene 64 bytes (P1363) y verifica con Web Crypto', async () => {
      expect(base64UrlToBytes(vector.signature)).toHaveLength(64);
      await expect(
        verifyCanonicalSignature({
          payload: vector.document,
          signatureB64u: vector.signature,
          publicKeyJwk: fixture.publicKeyJwk,
        }),
      ).resolves.toBe(true);
    });

    it('verifica directamente con crypto.subtle sobre los bytes UTF-8 canónicos', async () => {
      const key = await crypto.subtle.importKey(
        'jwk',
        { kty: 'EC', crv: 'P-256', x: fixture.publicKeyJwk.x, y: fixture.publicKeyJwk.y },
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );
      const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        base64UrlToBytes(vector.signature),
        utf8(vector.canonical),
      );
      expect(ok).toBe(true);
    });
  });
});

describe('P13 rechazo de contenido alterado', () => {
  const vector = fixture.vectors[0]!;
  const verifyWith = (payload: unknown, signatureB64u = vector.signature, publicKeyJwk: unknown = fixture.publicKeyJwk) =>
    verifyCanonicalSignature({ payload, signatureB64u, publicKeyJwk });

  it('la línea base verifica', async () => {
    await expect(verifyWith(vector.document)).resolves.toBe(true);
  });

  it('rechaza un campo con el valor cambiado', async () => {
    const doc = clone(vector.document) as Record<string, unknown>;
    const field = Object.keys(doc)[0]!;
    doc[field] = `${String(doc[field])}!`;
    await expect(verifyWith(doc)).resolves.toBe(false);
  });

  it('rechaza un campo numérico alterado en el último decimal', async () => {
    const numbers = fixture.vectors.find((v) => v.id === 'numbers')!;
    const doc = clone(numbers.document) as { integers: number[] };
    doc.integers[1] = 2;
    await expect(verifyWith(doc, numbers.signature)).resolves.toBe(false);
  });

  it('rechaza una clave añadida', async () => {
    const doc = clone(vector.document) as Record<string, unknown>;
    doc.extra = true;
    await expect(verifyWith(doc)).resolves.toBe(false);
  });

  it('rechaza una clave eliminada', async () => {
    const doc = clone(vector.document) as Record<string, unknown>;
    delete doc[Object.keys(doc)[0]!];
    await expect(verifyWith(doc)).resolves.toBe(false);
  });

  it('rechaza un cambio de tipo (número por cadena)', async () => {
    const doc = clone(vector.document) as Record<string, unknown>;
    doc.version = '1';
    await expect(verifyWith(doc)).resolves.toBe(false);
  });

  it('rechaza cada uno de los 512 bits de la firma volteados', async () => {
    for (let bit = 0; bit < 512; bit++) {
      expect(await verifyWith(vector.document, flipBit(vector.signature, bit))).toBe(false);
    }
  });

  it('rechaza la firma de otro documento', async () => {
    const other = fixture.vectors[1]!;
    await expect(verifyWith(vector.document, other.signature)).resolves.toBe(false);
  });

  it('rechaza con otra clave pública (par efímero distinto)', async () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    await expect(verifyWith(vector.document, vector.signature, other)).resolves.toBe(false);
  });

  it('devuelve false con firmas de longitud incorrecta o base64url inválido, nunca true', async () => {
    const bytes = base64UrlToBytes(vector.signature);
    const bad = [
      '',
      bytesToBase64Url(bytes.slice(0, 63)),
      bytesToBase64Url(new Uint8Array([...bytes, 0])),
      bytesToBase64Url(bytes.slice(0, 32)),
      `${vector.signature}=`,
      vector.signature.replace(/[A-Za-z0-9_-]/, '*'),
      'no es base64url!!',
      bytesToBase64Url(new Uint8Array(64)),
    ];
    for (const signatureB64u of bad) {
      expect(await verifyWith(vector.document, signatureB64u)).toBe(false);
    }
  });

  it('rechaza una firma DER en lugar de P1363', async () => {
    // Firma del mismo documento en DER: formato distinto del contrato, no debe aceptarse.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const der = sign('sha256', Buffer.from(vector.canonical, 'utf8'), privateKey);
    const jwk = publicKey.export({ format: 'jwk' });
    await expect(verifyWith(vector.document, der.toString('base64url'), jwk)).resolves.toBe(false);
  });

  it('un payload no canonicalizable lanza CanonicalizationError', async () => {
    await expect(verifyWith({ n: Number.NaN })).rejects.toBeInstanceOf(CanonicalizationError);
  });
});

describe('P13 importación de claves públicas', () => {
  it('importa como no extraíble y solo verify', async () => {
    const key = await importPublicKeyJwk(fixture.publicKeyJwk);
    expect(key.extractable).toBe(false);
    expect(key.usages).toEqual(['verify']);
    expect(key.type).toBe('public');
  });

  it('rechaza una JWK con material privado (d)', async () => {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const privateJwk = privateKey.export({ format: 'jwk' });
    expect(privateJwk.d).toBeTypeOf('string');
    await expect(importPublicKeyJwk(privateJwk)).rejects.toMatchObject({ code: 'PRIVATE_KEY_REJECTED' });
    await expect(
      verifyCanonicalSignature({ payload: {}, signatureB64u: 'AA', publicKeyJwk: privateJwk }),
    ).rejects.toBeInstanceOf(VerificationError);
  });

  it.each([
    ['curva distinta', { ...fixture.publicKeyJwk, crv: 'P-384' }],
    ['tipo distinto', { ...fixture.publicKeyJwk, kty: 'RSA' }],
    ['sin y', { kty: 'EC', crv: 'P-256', x: fixture.publicKeyJwk.x }],
    ['coordenada corta', { ...fixture.publicKeyJwk, x: 'AAAA' }],
    ['punto fuera de la curva', { kty: 'EC', crv: 'P-256', x: fixture.publicKeyJwk.x, y: fixture.publicKeyJwk.x }],
    ['no es objeto', 'clave'],
    ['null', null],
  ])('rechaza JWK inválida: %s', async (_name, jwk) => {
    await expect(importPublicKeyJwk(jwk)).rejects.toBeInstanceOf(VerificationError);
  });
});

describe('P13 interoperabilidad bidireccional Node <-> Web Crypto', () => {
  const documents: unknown[] = [
    { id: 'a1', msg: 'Alerta ñandú 😀', n: [1e30, 0.000001, -0] },
    { z: { y: [true, null, 'x'], a: 1 }, a: '\u0001\n' },
  ];

  it('firma en Node (ieee-p1363) y verifica con crypto.subtle', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    for (const doc of documents) {
      const signature = sign('sha256', Buffer.from(canonicalize(doc), 'utf8'), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      });
      expect(signature).toHaveLength(64);
      await expect(
        verifyCanonicalSignature({ payload: doc, signatureB64u: signature.toString('base64url'), publicKeyJwk: jwk }),
      ).resolves.toBe(true);
    }
  });

  it('firma con crypto.subtle y verifica con node:crypto (ieee-p1363)', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    for (const doc of documents) {
      const data = utf8(canonicalize(doc));
      const signature = new Uint8Array(
        await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data),
      );
      expect(signature).toHaveLength(64);
      const nodeKey = createPublicKey({ key: jwk, format: 'jwk' });
      expect(verify('sha256', data, { key: nodeKey, dsaEncoding: 'ieee-p1363' }, signature)).toBe(true);
      // y también con nuestra utilidad, que es lo que usará el navegador
      await expect(
        verifyCanonicalSignature({ payload: doc, signatureB64u: bytesToBase64Url(signature), publicKeyJwk: jwk }),
      ).resolves.toBe(true);
      // y se rechaza si Node recibe un documento alterado
      const tampered = utf8(canonicalize({ ...(doc as object), tampered: 1 }));
      expect(verify('sha256', tampered, { key: nodeKey, dsaEncoding: 'ieee-p1363' }, signature)).toBe(false);
    }
  });

  it('el kid calculado con Web Crypto coincide con el de node:crypto', async () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const expected = createHash('sha256').update(publicKey.export({ format: 'der', type: 'spki' })).digest('base64url');
    expect(await computeKid(publicKey.export({ format: 'jwk' }))).toBe(expected);
  });
});
