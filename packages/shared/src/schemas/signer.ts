import { z } from 'zod';
import {
  AlertaDocumentoSchema,
  EstadoDocumentoSchema,
  EventoDocumentoSchema,
  SignedEnvelopeSchema,
} from './documents.js';

/**
 * Protocolo API → firmante (canal interno: HTTP sobre socket Unix, `POST /sign`).
 * La API envía el documento SIN `key_id`: el firmante añade el de su clave activa, valida con estos
 * esquemas estrictos (cualquier campo extra o `tipo_doc` desconocido → 400), normaliza fechas a UTC
 * con segundos, canonicaliza con JCS y firma. El firmante no firma MANIFIESTO: eso es de la raíz offline.
 */
export const SignAlertaRequestSchema = AlertaDocumentoSchema.omit({ key_id: true });
export const SignEventoRequestSchema = EventoDocumentoSchema.omit({ key_id: true });
export const SignEstadoRequestSchema = EstadoDocumentoSchema.omit({ key_id: true });

export const SignRequestSchema = z.discriminatedUnion('tipo_doc', [
  SignAlertaRequestSchema,
  SignEventoRequestSchema,
  SignEstadoRequestSchema,
]);
export type SignRequest = z.infer<typeof SignRequestSchema>;

/** 200: sobre firmado. `payload_canonico` incluye el `key_id` que añadió el firmante. */
export const SignResponseSchema = SignedEnvelopeSchema;
export type SignResponse = z.infer<typeof SignResponseSchema>;

export const SIGNER_ERROR_CODES = ['INVALID_DOCUMENT', 'KEY_UNAVAILABLE', 'INTERNAL_ERROR'] as const;
/** 400 INVALID_DOCUMENT · 503 KEY_UNAVAILABLE · 500 INTERNAL_ERROR. Sin trazas ni rutas de archivos. */
export const SignerErrorSchema = z.object({
  code: z.enum(SIGNER_ERROR_CODES),
  message: z.string(),
});
export type SignerError = z.infer<typeof SignerErrorSchema>;

/** GET /health del firmante: nunca expone la clave privada, solo el key_id activo. */
export const SignerHealthSchema = z.object({
  status: z.literal('ok'),
  key_id: z.string(),
});
