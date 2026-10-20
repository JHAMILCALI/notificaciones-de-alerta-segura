import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { base64UrlToBytes, bytesToBase64Url, VerificationError } from '../src/index.ts';

describe('base64url', () => {
  it('coincide con los vectores de RFC 4648 §10 (sin relleno)', () => {
    const enc = new TextEncoder();
    const table: ReadonlyArray<readonly [string, string]> = [
      ['', ''],
      ['f', 'Zg'],
      ['fo', 'Zm8'],
      ['foo', 'Zm9v'],
      ['foob', 'Zm9vYg'],
      ['fooba', 'Zm9vYmE'],
      ['foobar', 'Zm9vYmFy'],
    ];
    for (const [text, b64] of table) {
      expect(bytesToBase64Url(enc.encode(text))).toBe(b64);
      expect(new TextDecoder().decode(base64UrlToBytes(b64))).toBe(text);
    }
  });

  it('usa el alfabeto URL-safe (- y _ en lugar de + y /)', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    expect(bytesToBase64Url(bytes)).toBe('-__-');
    expect([...base64UrlToBytes('-__-')]).toEqual([0xfb, 0xff, 0xfe]);
  });

  it('ida y vuelta con bytes aleatorios de todas las longitudes 0..130', () => {
    for (let length = 0; length <= 130; length++) {
      const bytes = new Uint8Array(randomBytes(length));
      const text = bytesToBase64Url(bytes);
      expect(text).toBe(Buffer.from(bytes).toString('base64url'));
      expect([...base64UrlToBytes(text)]).toEqual([...bytes]);
    }
  });

  it.each([
    ['relleno', 'Zg=='],
    ['alfabeto estándar +', 'a+b/'],
    ['espacio', 'Zm9v '],
    ['longitud imposible', 'Zm9vY'],
    ['bits sobrantes no nulos (2 chars)', 'Zh'],
    ['bits sobrantes no nulos (3 chars)', 'Zm9'],
    ['no ASCII', 'Zm9é'],
  ])('rechaza %s', (_name, text) => {
    expect(() => base64UrlToBytes(text)).toThrowError(VerificationError);
  });
});
