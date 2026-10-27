import { VerificationError } from './errors.ts';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP: Int8Array = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) table[ALPHABET.charCodeAt(i)] = i;
  return table;
})();

function char(index: number): string {
  return ALPHABET.charAt(index & 63);
}

/** Codifica bytes en base64url sin relleno (RFC 4648 §5). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += char(n >> 18) + char(n >> 12) + char(n >> 6) + char(n);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += char(n >> 18) + char(n >> 12);
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += char(n >> 18) + char(n >> 12) + char(n >> 6);
  }
  return out;
}

/**
 * Decodifica base64url estricto: sin relleno `=`, sin espacios, solo el alfabeto URL-safe y
 * con bits sobrantes a cero (codificación única). Lanza VerificationError('INVALID_BASE64URL').
 */
export function base64UrlToBytes(text: string): Uint8Array<ArrayBuffer> {
  if (text.length % 4 === 1) {
    throw new VerificationError('INVALID_BASE64URL', 'Longitud base64url imposible');
  }
  const values = new Array<number>(text.length);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const v = code < 128 ? LOOKUP[code]! : -1;
    if (v < 0) throw new VerificationError('INVALID_BASE64URL', 'Carácter no válido en base64url');
    values[i] = v;
  }
  const outLength = Math.floor((text.length * 6) / 8);
  const out = new Uint8Array(new ArrayBuffer(outLength));
  let o = 0;
  let i = 0;
  for (; i + 3 < values.length; i += 4) {
    const n = (values[i]! << 18) | (values[i + 1]! << 12) | (values[i + 2]! << 6) | values[i + 3]!;
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  const rest = values.length - i;
  if (rest === 2) {
    const n = (values[i]! << 18) | (values[i + 1]! << 12);
    if ((values[i + 1]! & 0x0f) !== 0) {
      throw new VerificationError('INVALID_BASE64URL', 'Bits sobrantes distintos de cero');
    }
    out[o++] = (n >> 16) & 255;
  } else if (rest === 3) {
    const n = (values[i]! << 18) | (values[i + 1]! << 12) | (values[i + 2]! << 6);
    if ((values[i + 2]! & 0x03) !== 0) {
      throw new VerificationError('INVALID_BASE64URL', 'Bits sobrantes distintos de cero');
    }
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
  }
  return out;
}
