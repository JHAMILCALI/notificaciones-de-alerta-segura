import { z } from 'zod';
import { NivelAlertaSchema, TipoAlertaSchema, ZonaSchema } from './drafts.js';

/**
 * Documentos firmados (§07 de la propuesta). Se firman como JCS (RFC 8785) con ECDSA P-256/SHA-256,
 * firma IEEE P1363 de 64 bytes en base64url. Los nombres de campo son los de la propuesta y forman
 * parte de los bytes firmados: cambiarlos invalida todas las firmas existentes.
 *
 * Reglas comunes:
 * - `tipo_doc` separa los tipos de documento (P16): una firma de EVENTO nunca vale como ALERTA.
 * - `version` es la versión del esquema del documento (no la del manifiesto). Hoy es 1.
 * - Fechas en ISO 8601 UTC con precisión de segundos: `2026-10-26T14:05:09Z`.
 * - Hashes en hexadecimal minúsculo de SHA-256 sobre los bytes canónicos exactos.
 * - `key_id` = SHA-256 (base64url) de la SPKI de la clave pública firmante.
 */
export const DOCUMENT_SCHEMA_VERSION = 1;

export const TIPOS_DOC = ['ALERTA', 'EVENTO', 'ESTADO', 'MANIFIESTO'] as const;
export const TipoDocSchema = z.enum(TIPOS_DOC);
export type TipoDoc = z.infer<typeof TipoDocSchema>;

/** ISO 8601 UTC con segundos exactos y sin fracciones. */
export const IsoUtcSecondsSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'Fecha ISO 8601 UTC con segundos (AAAA-MM-DDThh:mm:ssZ)');
export const Sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/, 'SHA-256 en hexadecimal minúsculo');
export const KeyIdSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'key_id: SHA-256 de la SPKI en base64url');
export const Base64UrlSchema = z.string().regex(/^[A-Za-z0-9_-]+$/, 'base64url sin relleno');
export const SignatureSchema = z.string().regex(/^[A-Za-z0-9_-]{86}$/, 'Firma P1363 de 64 bytes en base64url');

const docVersion = z.literal(DOCUMENT_SCHEMA_VERSION);

export const AlertaDocumentoSchema = z.strictObject({
  tipo_doc: z.literal('ALERTA'),
  version: docVersion,
  key_id: KeyIdSchema,
  alerta_id: z.uuid(),
  emisor_id: z.uuid(),
  tipo: TipoAlertaSchema,
  zona: ZonaSchema,
  severidad: NivelAlertaSchema,
  mensaje: z.string().min(10).max(1000),
  emitida_en: IsoUtcSecondsSchema,
  expira_en: IsoUtcSecondsSchema,
});
export type AlertaDocumento = z.infer<typeof AlertaDocumentoSchema>;

export const EventoDocumentoSchema = z.strictObject({
  tipo_doc: z.literal('EVENTO'),
  version: docVersion,
  key_id: KeyIdSchema,
  evento_id: z.uuid(),
  alerta_id: z.uuid(),
  /** SHA-256 de los bytes canónicos de la ALERTA que se cancela. */
  hash_alerta: Sha256HexSchema,
  emisor_id: z.uuid(),
  accion: z.literal('CANCELACION'),
  emitida_en: IsoUtcSecondsSchema,
});
export type EventoDocumento = z.infer<typeof EventoDocumentoSchema>;

export const ESTADOS_ALERTA = ['VIGENTE', 'CANCELADA', 'VENCIDA'] as const;
export const EstadoAlertaValorSchema = z.enum(ESTADOS_ALERTA);
export type EstadoAlertaValor = z.infer<typeof EstadoAlertaValorSchema>;

/** Estado firmado de corta duración (§07.3): protege frente a la supresión de cancelaciones. */
export const EstadoDocumentoSchema = z.strictObject({
  tipo_doc: z.literal('ESTADO'),
  version: docVersion,
  key_id: KeyIdSchema,
  alerta_id: z.uuid(),
  /** 0 sin eventos; +1 por cada evento aceptado. */
  secuencia: z.number().int().min(0),
  /** SHA-256 del último EVENTO; null si la alerta no tiene eventos. */
  ultimo_evento_hash: Sha256HexSchema.nullable(),
  estado: EstadoAlertaValorSchema,
  issued_at: IsoUtcSecondsSchema,
  /** issued_at + 10 minutos como máximo. */
  expires_at: IsoUtcSecondsSchema,
});
export type EstadoDocumento = z.infer<typeof EstadoDocumentoSchema>;
export const ESTADO_FRESCURA_MAX_SEGUNDOS = 600;

/** Clave pública ECDSA P-256 en JWK. Nunca contiene `d`. */
export const PublicJwkSchema = z.strictObject({
  kty: z.literal('EC'),
  crv: z.literal('P-256'),
  x: Base64UrlSchema,
  y: Base64UrlSchema,
});
export type PublicJwk = z.infer<typeof PublicJwkSchema>;

/**
 * Manifiesto de confianza (§07.2) firmado por la raíz de prueba con la CLI offline. Es la ÚNICA fuente
 * de confianza: la tabla de claves públicas de la BD es solo inventario.
 * Revocar una clave invalida TODAS sus firmas, sin mirar `emitida_en`.
 */
export const ManifiestoDocumentoSchema = z.strictObject({
  tipo_doc: z.literal('MANIFIESTO'),
  /** Número de manifiesto, estrictamente creciente: la PWA rechaza versiones inferiores a la ya vista. */
  version: z.number().int().min(1),
  /** key_id de la raíz que firma este manifiesto. */
  root_key_id: KeyIdSchema,
  issued_at: IsoUtcSecondsSchema,
  /** 24 h en la demostración, 7 días como máximo. */
  expires_at: IsoUtcSecondsSchema,
  key_id_activo: KeyIdSchema,
  claves: z.array(z.strictObject({ key_id: KeyIdSchema, jwk: PublicJwkSchema })).min(1),
  revocadas: z.array(KeyIdSchema),
  emisores_autorizados: z.array(z.uuid()),
});
export type ManifiestoDocumento = z.infer<typeof ManifiestoDocumentoSchema>;
export const MANIFIESTO_VIGENCIA_MAX_SEGUNDOS = 7 * 24 * 3600;

/**
 * Sobre de un documento firmado tal como viaja y se guarda. El receptor verifica la firma sobre
 * los bytes de `payload_canonico` y solo después interpreta su contenido: nunca reconstruye los
 * bytes a partir de campos sueltos.
 */
export const SignedEnvelopeSchema = z.strictObject({
  /** Bytes canónicos JCS (UTF-8) en base64url. */
  payload_canonico: Base64UrlSchema,
  hash_payload: Sha256HexSchema,
  firma: SignatureSchema,
  key_id: KeyIdSchema,
});
export type SignedEnvelope = z.infer<typeof SignedEnvelopeSchema>;
