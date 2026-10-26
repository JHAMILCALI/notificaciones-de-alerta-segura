import { z } from 'zod';
import { SignedEnvelopeSchema } from './documents.js';
import { NivelAlertaSchema, TipoAlertaSchema, ZonaSchema } from './drafts.js';

/**
 * Alertas publicadas (semana 2). Las lecturas son públicas (ciudadano sin sesión); no existe
 * ningún endpoint público de escritura.
 *
 * La API devuelve los sobres firmados tal como se guardaron. Los campos `resumen` son una copia
 * para listar y filtrar: la PWA (semana 3) solo confía en lo que verifica sobre `payload_canonico`.
 */
export const AlertaResumenSchema = z.object({
  tipo: TipoAlertaSchema,
  zona: ZonaSchema,
  severidad: NivelAlertaSchema,
  mensaje: z.string(),
  emitida_en: z.string(),
  expira_en: z.string(),
});

export const AlertaPublicadaSchema = z.object({
  id: z.uuid(),
  emisorId: z.uuid(),
  publishedAt: z.iso.datetime(),
  /** Copia NO verificada para mostrar en listados. */
  resumen: AlertaResumenSchema,
  /** Documento ALERTA firmado. */
  alerta: SignedEnvelopeSchema,
  /** Documentos EVENTO firmados, en orden de aceptación. */
  eventos: z.array(SignedEnvelopeSchema),
  /** Documento ESTADO firmado y fresco (≤ 10 min). */
  estado: SignedEnvelopeSchema,
});
export type AlertaPublicada = z.infer<typeof AlertaPublicadaSchema>;

/** GET /alerts/:alertaId → 200 · POST /drafts/:draftId/publish → 201 · POST /alerts/:alertaId/cancel → 201 */
export const AlertaResponseSchema = z.object({ alerta: AlertaPublicadaSchema });
export type AlertaResponse = z.infer<typeof AlertaResponseSchema>;

/** GET /alerts → 200, más recientes primero. */
export const AlertaListResponseSchema = z.object({ alertas: z.array(AlertaPublicadaSchema) });
export type AlertaListResponse = z.infer<typeof AlertaListResponseSchema>;

export const AlertaListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
});

export const AlertaIdParamSchema = z.object({ alertaId: z.uuid() });

/** POST /alerts/:alertaId/cancel: sin cuerpo (el evento lo construye el servidor). */
export const CancelAlertaRequestSchema = z.strictObject({});

/** GET /trust/manifest → 200: manifiesto firmado por la raíz, servido tal cual lo emitió la CLI. */
export const TrustManifestResponseSchema = z.object({ manifiesto: SignedEnvelopeSchema });
export type TrustManifestResponse = z.infer<typeof TrustManifestResponseSchema>;
