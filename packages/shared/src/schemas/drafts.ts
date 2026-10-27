import { z } from 'zod';
import {
  DEPARTAMENTOS,
  NIVELES_ALERTA,
  TIPOS_ALERTA,
  VIGENCIA_HORAS_MAX,
  VIGENCIA_HORAS_MIN,
} from '../constants/bolivia.js';

/**
 * Borradores con los campos oficiales (§08 de la propuesta, D-4 opción C). Son mutables y solo
 * los ve su dueño; al publicarse se firman y se copian a una alerta inmutable.
 */
export const TipoAlertaSchema = z.enum(TIPOS_ALERTA);
export const DepartamentoSchema = z.enum(DEPARTAMENTOS);
export const NivelAlertaSchema = z.enum(NIVELES_ALERTA);

/** Área afectada: departamento obligatorio y municipio o provincia opcional (null si no aplica). */
export const ZonaSchema = z.strictObject({
  departamento: DepartamentoSchema,
  municipio: z.string().trim().min(2).max(120).nullable(),
});
export type Zona = z.infer<typeof ZonaSchema>;

export const MensajeSchema = z.string().trim().min(10).max(1000);
export const VigenciaHorasSchema = z.number().int().min(VIGENCIA_HORAS_MIN).max(VIGENCIA_HORAS_MAX);

export const DraftStatusSchema = z.enum(['DRAFT', 'PUBLISHED']);
export type DraftStatus = z.infer<typeof DraftStatusSchema>;

export const CreateDraftRequestSchema = z.strictObject({
  tipo: TipoAlertaSchema,
  zona: ZonaSchema,
  severidad: NivelAlertaSchema,
  mensaje: MensajeSchema,
  vigenciaHoras: VigenciaHorasSchema,
});
export type CreateDraftRequest = z.infer<typeof CreateDraftRequestSchema>;

export const DraftSchema = z.object({
  id: z.uuid(),
  tipo: TipoAlertaSchema,
  zona: ZonaSchema,
  severidad: NivelAlertaSchema,
  mensaje: z.string(),
  vigenciaHoras: z.number().int(),
  status: DraftStatusSchema,
  ownerId: z.uuid(),
  /** Alerta publicada a partir de este borrador (null mientras sea DRAFT). */
  alertaId: z.uuid().nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
export type Draft = z.infer<typeof DraftSchema>;

/** POST /drafts → 201, GET /drafts/:id → 200 */
export const DraftResponseSchema = z.object({ draft: DraftSchema });
export type DraftResponse = z.infer<typeof DraftResponseSchema>;
/** GET /drafts → 200 (solo los del usuario autenticado) */
export const DraftListResponseSchema = z.object({ drafts: z.array(DraftSchema) });
export type DraftListResponse = z.infer<typeof DraftListResponseSchema>;

export const DraftIdParamSchema = z.object({ draftId: z.uuid() });
