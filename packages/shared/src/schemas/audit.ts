import { z } from 'zod';

export const AUDIT_ACTIONS = [
  'AUTH_LOGIN_SUCCEEDED',
  'AUTH_LOGIN_FAILED',
  'AUTH_LOGOUT',
  'AUTH_SESSION_REJECTED',
  'ISSUER_PROVISIONED',
  'ACCESS_DENIED',
  'CSRF_REJECTED',
  'RATE_LIMITED',
  'DRAFT_CREATED',
  'PUBLICATION_DENIED',
  'PUBLICATION_AUTHORIZED',
] as const;
export const AuditActionSchema = z.enum(AUDIT_ACTIONS);
export type AuditAction = z.infer<typeof AuditActionSchema>;

export const AuditOutcomeSchema = z.enum(['SUCCESS', 'DENIED', 'FAILURE']);
export type AuditOutcome = z.infer<typeof AuditOutcomeSchema>;

/** Registro de auditoría append-only. `metadata` nunca contiene contraseñas, tokens ni cookies. */
export const AuditEntrySchema = z.object({
  id: z.uuid(),
  occurredAt: z.iso.datetime(),
  action: AuditActionSchema,
  outcome: AuditOutcomeSchema,
  actorId: z.uuid().nullable(),
  targetType: z.string().nullable(),
  targetId: z.string().nullable(),
  ip: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()),
});
export type AuditEntry = z.infer<typeof AuditEntrySchema>;

export const AuditQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

/** GET /audit → 200 (ADMIN y AUDITOR) */
export const AuditListResponseSchema = z.object({ entries: z.array(AuditEntrySchema) });
export type AuditListResponse = z.infer<typeof AuditListResponseSchema>;
