import { z } from 'zod';

export const API_ERROR_CODES = [
  'VALIDATION_FAILED',
  'INVALID_CREDENTIALS',
  'UNAUTHENTICATED',
  'CSRF_INVALID',
  'FORBIDDEN',
  'NOT_FOUND',
  'CONFLICT',
  'RATE_LIMITED',
  'PUBLICATION_NOT_IMPLEMENTED',
  'INTERNAL_ERROR',
] as const;
export const ApiErrorCodeSchema = z.enum(API_ERROR_CODES);
export type ApiErrorCode = z.infer<typeof ApiErrorCodeSchema>;

/** Cuerpo de toda respuesta de error. Nunca incluye trazas ni detalles internos. */
export const ApiErrorSchema = z.object({
  statusCode: z.number().int(),
  code: ApiErrorCodeSchema,
  message: z.string(),
  /** Solo con VALIDATION_FAILED: campos rechazados, sin repetir los valores enviados. */
  issues: z.array(z.object({ path: z.string(), message: z.string() })).optional(),
});
export type ApiError = z.infer<typeof ApiErrorSchema>;
