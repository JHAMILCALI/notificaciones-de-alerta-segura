import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalize,
  CanonicalizationError,
  sha256Hex,
  VerificationError,
  verifyCanonicalSignature,
} from '@alertasegura/verification'
import fixture from '../../../../../tests/fixtures/crypto/p13-vectors.json'

export interface LabVector {
  id: string
  description: string
  document: unknown
  canonical: string
  sha256Hex: string
  signature: string
}

export interface LabFixture {
  publicKeyJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string; kid: string }
  vectors: LabVector[]
}

/** Vectores P13 generados en Node con una clave efímera (solo clave pública y firmas). */
export const labFixture: LabFixture = fixture as unknown as LabFixture

export type Evaluation =
  | { outcome: 'valid'; canonical: string; sha256: string }
  | { outcome: 'invalid'; canonical: string; sha256: string }
  | { outcome: 'error'; message: string }

/**
 * Canonicaliza (RFC 8785) el texto JSON dado y verifica la firma con Web Crypto.
 * `valid` = la firma corresponde exactamente a ese contenido; `invalid` = contenido o firma alterados.
 */
export async function evaluate(
  jsonText: string,
  signatureB64u: string,
  publicKeyJwk: LabFixture['publicKeyJwk'] = labFixture.publicKeyJwk,
): Promise<Evaluation> {
  let payload: unknown
  try {
    payload = JSON.parse(jsonText)
  } catch {
    return { outcome: 'error', message: 'El texto no es JSON válido.' }
  }
  try {
    const canonical = canonicalize(payload)
    const sha256 = await sha256Hex(canonical)
    const ok = await verifyCanonicalSignature({ payload, signatureB64u, publicKeyJwk })
    return { outcome: ok ? 'valid' : 'invalid', canonical, sha256 }
  } catch (error) {
    if (error instanceof CanonicalizationError || error instanceof VerificationError) {
      return { outcome: 'error', message: error.message }
    }
    return { outcome: 'error', message: 'No se pudo completar la verificación en este navegador.' }
  }
}

export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2)
}

/** Cambia un campo del documento (primera cadena o número) para demostrar que se rechaza. */
export function tamperField(jsonText: string): string {
  let value: unknown
  try {
    value = JSON.parse(jsonText)
  } catch {
    return jsonText
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return jsonText
  const record = value as Record<string, unknown>
  for (const [key, member] of Object.entries(record)) {
    if (typeof member === 'string') {
      record[key] = `${member} (alterado)`
      return prettyJson(record)
    }
    if (typeof member === 'number') {
      record[key] = member + 1
      return prettyJson(record)
    }
  }
  record.alterado = true
  return prettyJson(record)
}

export function addKey(jsonText: string): string {
  let value: unknown
  try {
    value = JSON.parse(jsonText)
  } catch {
    return jsonText
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return jsonText
  return prettyJson({ ...(value as Record<string, unknown>), claveExtra: true })
}

/** Invierte un bit de la firma (el primero del byte `index`). */
export function flipSignatureBit(signatureB64u: string, index = 0): string {
  const bytes = base64UrlToBytes(signatureB64u)
  const position = Math.min(index, bytes.length - 1)
  bytes[position] = (bytes[position] ?? 0) ^ 0x01
  return bytesToBase64Url(bytes)
}
