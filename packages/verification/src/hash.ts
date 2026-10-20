import { bytesToBase64Url } from './base64url.ts';

export async function sha256(data: BufferSource): Promise<ArrayBuffer> {
  return globalThis.crypto.subtle.digest('SHA-256', data);
}

/** Codifica una cadena en UTF-8. */
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(text);
  // Se copia a un ArrayBuffer propio para fijar el tipo sin afirmaciones.
  return new Uint8Array(encoded);
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** SHA-256 de una cadena UTF-8, en hexadecimal minúsculas. */
export async function sha256Hex(text: string): Promise<string> {
  return bytesToHex(new Uint8Array(await sha256(utf8(text))));
}

/** SHA-256 en base64url (formato de `kid`). */
export async function sha256Base64Url(data: BufferSource): Promise<string> {
  return bytesToBase64Url(new Uint8Array(await sha256(data)));
}
