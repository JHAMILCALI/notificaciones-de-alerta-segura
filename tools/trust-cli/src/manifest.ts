import { createHash, sign, type KeyObject } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  MANIFIESTO_VIGENCIA_MAX_SEGUNDOS,
  ManifiestoDocumentoSchema,
  SignedEnvelopeSchema,
  type ManifiestoDocumento,
  type PublicJwk,
  type SignedEnvelope,
} from '@alertasegura/shared';
import { bytesToBase64Url, canonicalize, computeKid, verifyManifest } from '@alertasegura/verification';
import { CliError } from './errors.ts';
import { readPrivateKey, readPublicJwk } from './keys.ts';

export const ROOT_PRIVATE_FILE = 'root.private.pem';
export const ROOT_PUBLIC_FILE = 'root.public.jwk.json';
const STATE_FILE = 'manifest-state.json';

export const MAX_HOURS = MANIFIESTO_VIGENCIA_MAX_SEGUNDOS / 3600;

export interface Root {
  privateKey: KeyObject;
  jwk: PublicJwk;
  keyId: string;
}

export async function loadRoot(rootDir: string): Promise<Root> {
  const privateKey = readPrivateKey(join(rootDir, ROOT_PRIVATE_FILE));
  const jwk = await readPublicJwk(join(rootDir, ROOT_PUBLIC_FILE));
  return { privateKey, jwk, keyId: await computeKid(jwk) };
}

/** ISO 8601 UTC con segundos (sin fracciones), como exige el contrato. */
export function isoSeconds(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function assertVersion(value: number): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new CliError('VERSION_INVALID', 'La versión debe ser un entero positivo');
  }
}

export function assertHours(value: number): void {
  if (!Number.isInteger(value) || value < 1 || value > MAX_HOURS) {
    throw new CliError('HOURS_INVALID', `La vigencia debe ser un entero entre 1 y ${MAX_HOURS} horas (7 días)`);
  }
}

/** Último manifiesto emitido por esta raíz (información pública), que fija el mínimo de versión. */
export function readState(rootDir: string): ManifiestoDocumento | null {
  const path = join(rootDir, STATE_FILE);
  if (!existsSync(path)) return null;
  const parsed = ManifiestoDocumentoSchema.safeParse(JSON.parse(readFileSync(path, 'utf8')));
  if (!parsed.success) {
    throw new CliError('STATE_INVALID', `${path} está dañado; no se emite nada hasta repararlo`);
  }
  return parsed.data;
}

export function requireState(rootDir: string): ManifiestoDocumento {
  const state = readState(rootDir);
  if (state === null) {
    throw new CliError('NO_PREVIOUS_MANIFEST', 'No hay manifiesto previo: emite el primero con issue-manifest');
  }
  return state;
}

export function assertNextVersion(state: ManifiestoDocumento | null, version: number): void {
  assertVersion(version);
  if (state !== null && version <= state.version) {
    throw new CliError(
      'VERSION_NOT_INCREASING',
      `La versión ${version} no supera la última emitida (${state.version}); usa ${state.version + 1} o más`,
    );
  }
}

export function hoursOf(manifest: ManifiestoDocumento): number {
  return Math.round((Date.parse(manifest.expires_at) - Date.parse(manifest.issued_at)) / 3_600_000);
}

export interface EmitInput {
  rootDir: string;
  root: Root;
  out: string;
  now: Date;
  hours: number;
  version: number;
  keyIdActivo: string;
  claves: ManifiestoDocumento['claves'];
  revocadas: string[];
  emisores: string[];
}

export interface EmitResult {
  manifest: ManifiestoDocumento;
  envelope: SignedEnvelope;
  hashPayload: string;
}

/**
 * Construye el manifiesto, lo firma con la raíz, lo comprueba con `verifyManifest` (el mismo código que
 * usará la PWA) y solo entonces lo escribe y avanza el estado de versiones.
 */
export async function emitManifest(input: EmitInput): Promise<EmitResult> {
  const issuedAt = new Date(Math.floor(input.now.getTime() / 1000) * 1000);
  const expiresAt = new Date(issuedAt.getTime() + input.hours * 3_600_000);
  const draft = {
    tipo_doc: 'MANIFIESTO',
    version: input.version,
    root_key_id: input.root.keyId,
    issued_at: isoSeconds(issuedAt),
    expires_at: isoSeconds(expiresAt),
    key_id_activo: input.keyIdActivo,
    claves: input.claves,
    revocadas: input.revocadas,
    emisores_autorizados: input.emisores,
  };
  const parsed = ManifiestoDocumentoSchema.safeParse(draft);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((i) => `${i.path.join('.') || '(raíz)'}: ${i.message}`).join('; ');
    throw new CliError('MANIFEST_INVALID', `El manifiesto no cumple el contrato: ${detail}`);
  }
  const manifest = parsed.data;

  const bytes = Buffer.from(canonicalize(manifest), 'utf8');
  const envelope = SignedEnvelopeSchema.parse({
    payload_canonico: bytesToBase64Url(bytes),
    hash_payload: createHash('sha256').update(bytes).digest('hex'),
    firma: bytesToBase64Url(sign('sha256', bytes, { key: input.root.privateKey, dsaEncoding: 'ieee-p1363' })),
    key_id: input.root.keyId,
  });

  // Autocomprobación: lo que sale de la CLI debe verificar con el código de producción.
  await verifyManifest({ envelope, rootJwk: input.root.jwk, ahora: issuedAt, versionMinima: input.version });

  mkdirSync(dirname(input.out), { recursive: true });
  writeFileSync(input.out, `${JSON.stringify(envelope, null, 2)}\n`);
  const statePath = join(input.rootDir, STATE_FILE);
  const tmp = `${statePath}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(manifest, null, 2)}\n`);
  renameSync(tmp, statePath);
  return { manifest, envelope, hashPayload: envelope.hash_payload };
}
