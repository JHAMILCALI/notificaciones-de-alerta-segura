import { z } from 'zod';

/**
 * Borradores mínimos de la semana 1: existen para demostrar la autorización por propiedad.
 * El ciclo de vida completo (revisión, publicación firmada, revocación) es de semanas posteriores.
 */
export const SeveritySchema = z.enum(['INFO', 'WARNING', 'CRITICAL']);
export type Severity = z.infer<typeof SeveritySchema>;

export const DraftStatusSchema = z.enum(['DRAFT']);

export const CreateDraftRequestSchema = z.strictObject({
  title: z.string().trim().min(5).max(140),
  body: z.string().trim().min(10).max(4000),
  severity: SeveritySchema,
});
export type CreateDraftRequest = z.infer<typeof CreateDraftRequestSchema>;

export const DraftSchema = z.object({
  id: z.uuid(),
  title: z.string(),
  body: z.string(),
  severity: SeveritySchema,
  status: DraftStatusSchema,
  ownerId: z.uuid(),
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
