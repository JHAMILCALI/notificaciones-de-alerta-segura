import { join } from 'node:path';
import { type ManifiestoDocumento } from '@alertasegura/shared';
import { computeKid } from '@alertasegura/verification';
import { CliError } from './errors.ts';
import { generateP256, readPublicJwk, writeNewFile } from './keys.ts';
import {
  assertHours,
  assertNextVersion,
  emitManifest,
  hoursOf,
  loadRoot,
  readState,
  requireState,
  ROOT_PRIVATE_FILE,
  ROOT_PUBLIC_FILE,
} from './manifest.ts';
import { assertOutsideRepo, assertPrivateOutputAllowed } from './paths.ts';

export const SIGNER_PRIVATE_FILE = 'private.pem';
export const SIGNER_PUBLIC_FILE = 'public.jwk.json';

export interface ManifestSummary {
  version: number;
  issuedAt: string;
  expiresAt: string;
  keyIdActivo: string;
  revocadas: string[];
  out: string;
}

function summarize(manifest: ManifiestoDocumento, out: string): ManifestSummary {
  return {
    version: manifest.version,
    issuedAt: manifest.issued_at,
    expiresAt: manifest.expires_at,
    keyIdActivo: manifest.key_id_activo,
    revocadas: manifest.revocadas,
    out,
  };
}

export interface InitRootOptions {
  rootDir: string;
}

/** Genera la raíz P-256 fuera del repositorio. La privada queda en PKCS#8 PEM con modo 0600. */
export async function initRoot(options: InitRootOptions): Promise<{ rootDir: string; keyId: string }> {
  const rootDir = assertOutsideRepo(options.rootDir, 'La clave raíz');
  const key = await generateP256();
  writeNewFile(join(rootDir, ROOT_PRIVATE_FILE), key.privatePem, 0o600);
  writeNewFile(join(rootDir, ROOT_PUBLIC_FILE), `${JSON.stringify(key.jwk, null, 2)}\n`, 0o644);
  return { rootDir, keyId: key.keyId };
}

export interface KeygenSignerOptions {
  /** Carpeta de salida (por ejemplo `secrets/signer`): fuera del repositorio o bajo `secrets/`. */
  out: string;
}

/** Genera la clave del firmante: privada PKCS#8 PEM (0400) y pública JWK. */
export async function keygenSigner(options: KeygenSignerOptions): Promise<{ out: string; keyId: string }> {
  const privatePath = assertPrivateOutputAllowed(join(options.out, SIGNER_PRIVATE_FILE), 'La clave privada del firmante');
  const key = await generateP256();
  writeNewFile(privatePath, key.privatePem, 0o400);
  writeNewFile(join(options.out, SIGNER_PUBLIC_FILE), `${JSON.stringify(key.jwk, null, 2)}\n`, 0o644);
  return { out: options.out, keyId: key.keyId };
}

export interface IssueManifestOptions {
  rootDir: string;
  version: number;
  hours: number;
  signerJwkPath: string;
  issuers: string[];
  out: string;
  now?: Date;
}

/** Emite el MANIFIESTO firmado por la raíz con el firmante indicado como clave activa. */
export async function issueManifest(options: IssueManifestOptions): Promise<ManifestSummary> {
  assertHours(options.hours);
  const state = readState(options.rootDir);
  assertNextVersion(state, options.version);
  const root = await loadRoot(options.rootDir);
  const jwk = await readPublicJwk(options.signerJwkPath);
  const signerId = await computeKid(jwk);
  if (state?.revocadas.includes(signerId)) {
    throw new CliError('KEY_REVOKED', `La clave ${signerId} está revocada y no puede volver a ser la activa`);
  }
  const claves = [...(state?.claves ?? []).filter((c) => c.key_id !== signerId), { key_id: signerId, jwk }];
  const result = await emitManifest({
    rootDir: options.rootDir,
    root,
    out: options.out,
    now: options.now ?? new Date(),
    hours: options.hours,
    version: options.version,
    keyIdActivo: signerId,
    claves,
    revocadas: state?.revocadas ?? [],
    emisores: options.issuers,
  });
  return summarize(result.manifest, options.out);
}

export interface RevokeOptions {
  rootDir: string;
  keyId: string;
  version: number;
  out: string;
  hours?: number;
  now?: Date;
}

/** Emite un manifiesto nuevo con `keyId` en `revocadas`. Revocar invalida TODAS sus firmas. */
export async function revoke(options: RevokeOptions): Promise<ManifestSummary> {
  const state = requireState(options.rootDir);
  assertNextVersion(state, options.version);
  const hours = options.hours ?? hoursOf(state);
  assertHours(hours);
  if (!state.claves.some((c) => c.key_id === options.keyId)) {
    throw new CliError('KEY_UNKNOWN', `La clave ${options.keyId} no figura en el manifiesto vigente`);
  }
  if (state.revocadas.includes(options.keyId)) {
    throw new CliError('KEY_ALREADY_REVOKED', `La clave ${options.keyId} ya estaba revocada`);
  }
  if (state.key_id_activo === options.keyId) {
    throw new CliError(
      'ACTIVE_KEY',
      'La clave activa no se revoca sin sustituta: usa rotate --revoke-previous para cambiarla y revocarla a la vez',
    );
  }
  const root = await loadRoot(options.rootDir);
  const result = await emitManifest({
    rootDir: options.rootDir,
    root,
    out: options.out,
    now: options.now ?? new Date(),
    hours,
    version: options.version,
    keyIdActivo: state.key_id_activo,
    claves: state.claves,
    revocadas: [...state.revocadas, options.keyId],
    emisores: state.emisores_autorizados,
  });
  return summarize(result.manifest, options.out);
}

export interface RotateOptions {
  rootDir: string;
  version: number;
  /** Carpeta de la clave nueva del firmante (por defecto `secrets/signer-v<versión>`). */
  signerOut: string;
  out: string;
  hours?: number;
  /** Si es true la anterior pasa a `revocadas`; si no, queda retirada (sus firmas antiguas siguen válidas). */
  revokePrevious?: boolean;
  now?: Date;
}

/** Genera una clave nueva del firmante, la activa y retira o revoca la anterior. */
export async function rotate(options: RotateOptions): Promise<ManifestSummary & { signerKeyId: string }> {
  const state = requireState(options.rootDir);
  assertNextVersion(state, options.version);
  const hours = options.hours ?? hoursOf(state);
  assertHours(hours);
  const root = await loadRoot(options.rootDir);
  // Todo se valida antes de generar la clave para no dejar una clave huérfana.
  const generated = await keygenSigner({ out: options.signerOut });
  const jwk = await readPublicJwk(join(options.signerOut, SIGNER_PUBLIC_FILE));
  const result = await emitManifest({
    rootDir: options.rootDir,
    root,
    out: options.out,
    now: options.now ?? new Date(),
    hours,
    version: options.version,
    keyIdActivo: generated.keyId,
    claves: [...state.claves, { key_id: generated.keyId, jwk }],
    revocadas: options.revokePrevious ? [...state.revocadas, state.key_id_activo] : state.revocadas,
    emisores: state.emisores_autorizados,
  });
  return { ...summarize(result.manifest, options.out), signerKeyId: generated.keyId };
}
