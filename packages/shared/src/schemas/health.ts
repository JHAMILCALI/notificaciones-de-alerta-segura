import { z } from 'zod';

/** GET /health → 200 si la API responde y PostgreSQL acepta consultas; 503 en caso contrario. */
export const HealthResponseSchema = z.object({
  status: z.enum(['ok', 'degraded']),
  database: z.enum(['up', 'down']),
});
export type HealthResponse = z.infer<typeof HealthResponseSchema>;
