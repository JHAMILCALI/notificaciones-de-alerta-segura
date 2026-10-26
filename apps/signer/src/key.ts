import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { computeKid } from '@alertasegura/verification';

export interface LoadedKey {
  privateKey: KeyObject;
  keyId: string;
}

/**
 * Lee la clave privada PKCS#8 PEM UNA sola vez. Devuelve `null` si falta, no se puede leer o no es
 * ECDSA P-256: el firmante arranca igualmente y responde 503 `KEY_UNAVAILABLE`. Nunca se registra la
 * ruta ni el contenido del archivo.
 */
export async function loadSigningKey(path: string | undefined): Promise<LoadedKey | null> {
  if (path === undefined) return null;
  try {
    const privateKey = createPrivateKey(readFileSync(path, 'utf8'));
    if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
      return null;
    }
    const { kty, crv, x, y } = createPublicKey(privateKey).export({ format: 'jwk' });
    return { privateKey, keyId: await computeKid({ kty, crv, x, y }) };
  } catch {
    return null;
  }
}
