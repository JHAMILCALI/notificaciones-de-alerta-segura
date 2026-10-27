import { Algorithm, hash, verify } from '@node-rs/argon2';

/**
 * Argon2id con los parámetros mínimos de OWASP: m=19456 KiB, t=2, p=1.
 * Fuente única: la usan la API (login, provisión) y el seed.
 */
export const ARGON2_OPTIONS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

export function hashPassword(password: string): Promise<string> {
  return hash(password, ARGON2_OPTIONS);
}

/** Devuelve false (nunca lanza) si el hash está mal formado. */
export async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}
