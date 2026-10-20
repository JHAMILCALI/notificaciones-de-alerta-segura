import { base64UrlToBytes } from './base64url.ts';
import { canonicalize } from './canonicalize.ts';
import { VerificationError } from './errors.ts';
import { sha256Base64Url, utf8 } from './hash.ts';

export interface VerificationInput {
  payload: BufferSource;
  signature: BufferSource;
  publicKey: CryptoKey;
}

/** Clave pública EC P-256 en JWK. `kid` es opcional y no interviene en la verificación. */
export interface PublicKeyJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  kid?: string;
}

const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
/** Una firma ECDSA P-256 en formato IEEE P1363 es r‖s con 32 bytes cada uno. */
export const P1363_SIGNATURE_LENGTH = 64;

export async function verifyEcdsa(input: VerificationInput): Promise<boolean> {
  return globalThis.crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    input.publicKey,
    input.signature,
    input.payload,
  );
}

function cleanPublicJwk(input: unknown): { kty: 'EC'; crv: 'P-256'; x: string; y: string } {
  if (typeof input !== 'object' || input === null) {
    throw new VerificationError('INVALID_PUBLIC_KEY', 'La JWK debe ser un objeto');
  }
  const jwk = input as Record<string, unknown>;
  // Cualquier material privado (d, p, q, dp, dq, qi, oth, k) se rechaza explícitamente.
  for (const privateField of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    if (privateField in jwk) {
      throw new VerificationError('PRIVATE_KEY_REJECTED', 'La JWK contiene material de clave privada');
    }
  }
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new VerificationError('INVALID_PUBLIC_KEY', 'Solo se admiten claves EC P-256');
  }
  const { x, y } = jwk;
  if (typeof x !== 'string' || typeof y !== 'string') {
    throw new VerificationError('INVALID_PUBLIC_KEY', 'Faltan las coordenadas x e y');
  }
  let xLength: number;
  let yLength: number;
  try {
    xLength = base64UrlToBytes(x).length;
    yLength = base64UrlToBytes(y).length;
  } catch {
    throw new VerificationError('INVALID_PUBLIC_KEY', 'Coordenadas con base64url no válido');
  }
  if (xLength !== 32 || yLength !== 32) {
    throw new VerificationError('INVALID_PUBLIC_KEY', 'Las coordenadas deben tener 32 bytes');
  }
  return { kty: 'EC', crv: 'P-256', x, y };
}

/**
 * Importa una clave pública JWK como no extraíble y solo para `verify`.
 * Rechaza cualquier JWK que incluya `d` u otro material privado.
 */
export async function importPublicKeyJwk(jwk: unknown): Promise<CryptoKey> {
  const clean = cleanPublicJwk(jwk);
  try {
    return await globalThis.crypto.subtle.importKey('jwk', clean, ECDSA_P256, false, ['verify']);
  } catch {
    // Punto fuera de la curva u otro defecto de la clave.
    throw new VerificationError('INVALID_PUBLIC_KEY', 'La clave pública no es un punto válido de P-256');
  }
}

/** `kid` = SHA-256 (base64url) de la SPKI DER de la clave pública. */
export async function computeKid(jwk: unknown): Promise<string> {
  const clean = cleanPublicJwk(jwk);
  let key: CryptoKey;
  try {
    // Clave pública: puede ser extraíble sin riesgo, solo para derivar la huella.
    key = await globalThis.crypto.subtle.importKey('jwk', clean, ECDSA_P256, true, ['verify']);
  } catch {
    throw new VerificationError('INVALID_PUBLIC_KEY', 'La clave pública no es un punto válido de P-256');
  }
  return sha256Base64Url(await globalThis.crypto.subtle.exportKey('spki', key));
}

export interface CanonicalSignatureInput {
  /** Documento JSON (se canonicaliza con JCS antes de verificar). */
  payload: unknown;
  /** Firma IEEE P1363 (64 bytes) en base64url. */
  signatureB64u: string;
  publicKeyJwk: unknown;
}

/**
 * Canonicaliza `payload` (RFC 8785), lo codifica en UTF-8 y verifica ECDSA P-256 / SHA-256.
 * Devuelve `false` si la firma es inválida, mal codificada o de longitud incorrecta.
 * Lanza CanonicalizationError si el payload no es JSON canonicalizable y VerificationError si la
 * clave es inválida o contiene material privado.
 */
export async function verifyCanonicalSignature(input: CanonicalSignatureInput): Promise<boolean> {
  const key = await importPublicKeyJwk(input.publicKeyJwk);
  const data = utf8(canonicalize(input.payload));
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = base64UrlToBytes(input.signatureB64u);
  } catch {
    return false;
  }
  if (signature.length !== P1363_SIGNATURE_LENGTH) return false;
  return verifyEcdsa({ payload: data, signature, publicKey: key });
}
