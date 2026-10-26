import {
  AlertaDocumentoSchema,
  EstadoDocumentoSchema,
  EventoDocumentoSchema,
  MANIFIESTO_VIGENCIA_MAX_SEGUNDOS,
  ManifiestoDocumentoSchema,
  SignedEnvelopeSchema,
  type AlertaDocumento,
  type EstadoDocumento,
  type EventoDocumento,
  type ManifiestoDocumento,
} from '@alertasegura/shared';
import { base64UrlToBytes } from './base64url.ts';
import { canonicalize } from './canonicalize.ts';
import { VerificationError } from './errors.ts';
import { bytesToHex, sha256, utf8 } from './hash.ts';
import { computeKid, importPublicKeyJwk, P1363_SIGNATURE_LENGTH, verifyEcdsa } from './verify.ts';

/** Tipos que firma el firmante de la API. MANIFIESTO lo firma la raíz offline: ver `verifyManifest`. */
export interface DocumentosPorTipo {
  ALERTA: AlertaDocumento;
  EVENTO: EventoDocumento;
  ESTADO: EstadoDocumento;
}
export type TipoDocFirmante = keyof DocumentosPorTipo;

const PAYLOAD_SCHEMAS = {
  ALERTA: AlertaDocumentoSchema,
  EVENTO: EventoDocumentoSchema,
  ESTADO: EstadoDocumentoSchema,
} as const;

export interface VerifyDocumentInput<T extends TipoDocFirmante> {
  /** Sobre tal como viaja: se valida con `SignedEnvelopeSchema` (estricto). */
  envelope: unknown;
  /** Clave pública del firmante (JWK). Se rechaza cualquier JWK con material privado. */
  jwk: unknown;
  tipoEsperado: T;
}

export interface VerifyManifestInput {
  envelope: unknown;
  /** Raíz de confianza anclada (JWK pública). */
  rootJwk: unknown;
  ahora: Date;
  /** Versión mínima aceptable: la mayor ya vista por el cliente. */
  versionMinima: number;
}

interface VerifiedPayload {
  /** Objeto ya interpretado a partir de los bytes firmados. */
  payload: Record<string, unknown>;
  keyId: string;
}

/**
 * Pasos comunes: sobre estricto → `key_id` del sobre = huella de la JWK → hash de los bytes →
 * firma sobre los bytes → bytes en forma canónica JCS. Solo después se interpreta el contenido:
 * los bytes nunca se reconstruyen a partir de campos sueltos.
 */
async function verifySignedBytes(envelopeInput: unknown, jwk: unknown): Promise<VerifiedPayload> {
  const parsed = SignedEnvelopeSchema.safeParse(envelopeInput);
  if (!parsed.success) {
    throw new VerificationError('INVALID_ENVELOPE', 'El sobre firmado no cumple el contrato');
  }
  const envelope = parsed.data;

  // Lanza PRIVATE_KEY_REJECTED / INVALID_PUBLIC_KEY antes de tocar nada más.
  const publicKey = await importPublicKeyJwk(jwk);
  if ((await computeKid(jwk)) !== envelope.key_id) {
    throw new VerificationError('KEY_ID_MISMATCH', 'El key_id del sobre no corresponde a la clave indicada');
  }

  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = base64UrlToBytes(envelope.payload_canonico);
  } catch {
    throw new VerificationError('INVALID_ENVELOPE', 'payload_canonico no es base64url válido');
  }
  if (bytesToHex(new Uint8Array(await sha256(bytes))) !== envelope.hash_payload) {
    throw new VerificationError('HASH_MISMATCH', 'hash_payload no coincide con los bytes del payload');
  }

  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = base64UrlToBytes(envelope.firma);
  } catch {
    throw new VerificationError('SIGNATURE_INVALID', 'La firma no es base64url válido');
  }
  if (signature.length !== P1363_SIGNATURE_LENGTH || !(await verifyEcdsa({ payload: bytes, signature, publicKey }))) {
    throw new VerificationError('SIGNATURE_INVALID', 'La firma no es válida para esos bytes y esa clave');
  }

  let text: string;
  let value: unknown;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    value = JSON.parse(text);
  } catch {
    throw new VerificationError('INVALID_PAYLOAD', 'El payload firmado no es JSON UTF-8 válido');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VerificationError('INVALID_PAYLOAD', 'El payload firmado debe ser un objeto JSON');
  }
  let canonical: string;
  try {
    canonical = canonicalize(value);
  } catch {
    throw new VerificationError('INVALID_PAYLOAD', 'El payload firmado no es canonicalizable');
  }
  if (canonical !== text) {
    throw new VerificationError('NOT_CANONICAL', 'Los bytes firmados no están en forma canónica JCS');
  }
  return { payload: value as Record<string, unknown>, keyId: envelope.key_id };
}

/**
 * Verifica un documento ALERTA, EVENTO o ESTADO. Devuelve el documento solo si todo pasa:
 * firma válida sobre los bytes, hash, `key_id` (sobre = payload = huella de la JWK), `tipo_doc`
 * igual al esperado (P16) y payload válido según el esquema Zod estricto de su tipo.
 * Lanza `VerificationError` con el motivo en `code`.
 */
export async function verifyDocument<T extends TipoDocFirmante>(
  input: VerifyDocumentInput<T>,
): Promise<DocumentosPorTipo[T]> {
  const { payload, keyId } = await verifySignedBytes(input.envelope, input.jwk);
  if (payload.tipo_doc !== input.tipoEsperado) {
    throw new VerificationError(
      'TIPO_DOC_MISMATCH',
      `tipo_doc ${JSON.stringify(payload.tipo_doc)} distinto del esperado (${input.tipoEsperado})`,
    );
  }
  const schema = PAYLOAD_SCHEMAS[input.tipoEsperado];
  const result = schema.safeParse(payload);
  if (!result.success) {
    throw new VerificationError('INVALID_PAYLOAD', `El payload ${input.tipoEsperado} no cumple su esquema`);
  }
  if (result.data.key_id !== keyId) {
    throw new VerificationError('KEY_ID_MISMATCH', 'El key_id del payload no coincide con el del sobre');
  }
  // El esquema de cada tipo garantiza la forma; TypeScript no puede enlazar T con el esquema elegido.
  return result.data as DocumentosPorTipo[T];
}

/**
 * Verifica el manifiesto de confianza con la raíz anclada: firma, `root_key_id`, vigencia
 * (`expires_at` en el futuro y como máximo 7 días desde `issued_at`), `version` ≥ `versionMinima`
 * y coherencia interna (clave activa presente y no revocada; cada `key_id` es la huella de su JWK).
 */
export async function verifyManifest(input: VerifyManifestInput): Promise<ManifiestoDocumento> {
  const { payload, keyId } = await verifySignedBytes(input.envelope, input.rootJwk);
  if (payload.tipo_doc !== 'MANIFIESTO') {
    throw new VerificationError(
      'TIPO_DOC_MISMATCH',
      `tipo_doc ${JSON.stringify(payload.tipo_doc)} distinto del esperado (MANIFIESTO)`,
    );
  }
  const result = ManifiestoDocumentoSchema.safeParse(payload);
  if (!result.success) {
    throw new VerificationError('INVALID_PAYLOAD', 'El payload MANIFIESTO no cumple su esquema');
  }
  const manifest = result.data;
  if (manifest.root_key_id !== keyId) {
    throw new VerificationError('KEY_ID_MISMATCH', 'root_key_id no coincide con la raíz que firmó el manifiesto');
  }

  const issuedAt = Date.parse(manifest.issued_at);
  const expiresAt = Date.parse(manifest.expires_at);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)) {
    throw new VerificationError('INVALID_PAYLOAD', 'Fechas del manifiesto no válidas');
  }
  if (expiresAt <= input.ahora.getTime()) {
    throw new VerificationError('MANIFEST_EXPIRED', 'El manifiesto ha caducado');
  }
  if (expiresAt <= issuedAt || (expiresAt - issuedAt) / 1000 > MANIFIESTO_VIGENCIA_MAX_SEGUNDOS) {
    throw new VerificationError('MANIFEST_TOO_LONG', 'La vigencia del manifiesto supera los 7 días');
  }
  if (manifest.version < input.versionMinima) {
    throw new VerificationError(
      'MANIFEST_VERSION_TOO_LOW',
      `Versión ${manifest.version} inferior a la mínima aceptable (${input.versionMinima})`,
    );
  }

  for (const clave of manifest.claves) {
    if ((await computeKid(clave.jwk)) !== clave.key_id) {
      throw new VerificationError('MANIFEST_INCONSISTENT', 'Un key_id del manifiesto no es la huella de su JWK');
    }
  }
  if (!manifest.claves.some((c) => c.key_id === manifest.key_id_activo)) {
    throw new VerificationError('MANIFEST_INCONSISTENT', 'key_id_activo no figura entre las claves');
  }
  if (manifest.revocadas.includes(manifest.key_id_activo)) {
    throw new VerificationError('MANIFEST_INCONSISTENT', 'La clave activa figura como revocada');
  }
  return manifest;
}

/**
 * Verifica que un EVENTO de cancelación es legítimo para su ALERTA (P06). Ambos documentos deben
 * verificar con la misma clave y además: el evento nombra la misma `alerta_id`, su `hash_alerta` es el
 * SHA-256 de los bytes exactos de la ALERTA (`hash_payload`) y lo emite el mismo `emisor_id`.
 * Lanza `VerificationError`; devuelve ambos documentos solo si todo pasa.
 */
export async function verifyCancelacion(
  alertaEnvelope: unknown,
  eventoEnvelope: unknown,
  jwk: unknown,
): Promise<{ alerta: AlertaDocumento; evento: EventoDocumento }> {
  const alerta = await verifyDocument({ envelope: alertaEnvelope, jwk, tipoEsperado: 'ALERTA' });
  const evento = await verifyDocument({ envelope: eventoEnvelope, jwk, tipoEsperado: 'EVENTO' });
  if (evento.alerta_id !== alerta.alerta_id) {
    throw new VerificationError('CANCELACION_ALERTA_MISMATCH', 'El evento no corresponde a esta alerta');
  }
  // verifyDocument ya validó el sobre de la alerta: su hash_payload es el SHA-256 de los bytes firmados.
  const { hash_payload: hashAlerta } = alertaEnvelope as { hash_payload: string };
  if (evento.hash_alerta !== hashAlerta) {
    throw new VerificationError('CANCELACION_HASH_MISMATCH', 'hash_alerta no coincide con los bytes de la alerta');
  }
  if (evento.emisor_id !== alerta.emisor_id) {
    throw new VerificationError('CANCELACION_EMISOR_MISMATCH', 'El evento lo emite otro emisor distinto del de la alerta');
  }
  return { alerta, evento };
}

/** Texto UTF-8 de los bytes canónicos de un documento (utilidad para firmantes y pruebas). */
export function canonicalBytes(document: unknown): Uint8Array<ArrayBuffer> {
  return utf8(canonicalize(document));
}
