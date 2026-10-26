import { execFileSync } from 'node:child_process';
import path from 'node:path';
import type { PublicJwk, SignedEnvelope } from '@alertasegura/shared';

export interface EnvelopeVerification {
  /** Documento JSON interpretado a partir de los bytes firmados. */
  document: Record<string, unknown>;
  canonical: boolean;
  hashOk: boolean;
  keyIdOk: boolean;
  signatureOk: boolean;
}

/**
 * Verifica sobres con `@alertasegura/verification` (canonicalización JCS, SHA-256, key_id y ECDSA P-256),
 * tal como lo hará la PWA. Corre en un proceso Node aparte porque el paquete es ESM puro.
 */
export function verifyWithPackage(
  envelopes: SignedEnvelope[],
  jwk: PublicJwk,
): EnvelopeVerification[] {
  const script = path.resolve(__dirname, 'verify-with-package.mjs');
  const out = execFileSync(process.execPath, [script], {
    input: JSON.stringify({ jwk, envelopes }),
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return JSON.parse(out) as EnvelopeVerification[];
}

/** Atajo: todas las comprobaciones de un sobre deben ser verdaderas. */
export function expectValid(v: EnvelopeVerification): void {
  expect(v).toMatchObject({
    canonical: true,
    hashOk: true,
    keyIdOk: true,
    signatureOk: true,
  });
}
