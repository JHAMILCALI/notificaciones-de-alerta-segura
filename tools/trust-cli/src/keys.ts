import { createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { PublicJwkSchema, type PublicJwk } from '@alertasegura/shared';
import { computeKid, importPublicKeyJwk } from '@alertasegura/verification';
import { CliError } from './errors.ts';

export interface GeneratedKey {
  privatePem: string;
  jwk: PublicJwk;
  keyId: string;
}

/** ECDSA P-256. La privada sale en PKCS#8 PEM y la pública en JWK limpia (sin `d`). */
export async function generateP256(): Promise<GeneratedKey> {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { kty, crv, x, y } = publicKey.export({ format: 'jwk' });
  const jwk = PublicJwkSchema.parse({ kty, crv, x, y });
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    jwk,
    keyId: await computeKid(jwk),
  };
}

/** Crea el archivo con permisos restrictivos y falla si ya existe: nunca se pisa una clave. */
export function writeNewFile(path: string, data: string, mode: number): void {
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(path, data, { flag: 'wx', mode });
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'EEXIST') {
      throw new CliError('FILE_EXISTS', `Ya existe ${path}; no se sobrescribe`);
    }
    throw error;
  }
}

export function readPrivateKey(path: string): KeyObject {
  let pem: string;
  try {
    pem = readFileSync(path, 'utf8');
  } catch {
    throw new CliError('KEY_NOT_FOUND', `No se pudo leer la clave privada en ${path}`);
  }
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new CliError('KEY_INVALID', 'La clave privada debe ser ECDSA P-256');
  }
  return key;
}

/** Lee una JWK pública; rechaza cualquier archivo con material privado. */
export async function readPublicJwk(path: string): Promise<PublicJwk> {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new CliError('JWK_UNREADABLE', `No se pudo leer la JWK pública en ${path}`);
  }
  try {
    await importPublicKeyJwk(raw);
  } catch {
    throw new CliError('JWK_INVALID', `${path} no es una JWK pública P-256 válida (¿contiene la clave privada?)`);
  }
  const { kty, crv, x, y } = raw as PublicJwk;
  return { kty, crv, x, y };
}
