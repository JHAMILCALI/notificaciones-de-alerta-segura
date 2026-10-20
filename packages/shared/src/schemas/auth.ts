import { z } from 'zod';
import { PASSWORD_MAX_LENGTH } from '../constants/http.js';
import { PERMISSIONS, ROLES } from '../constants/roles.js';

export const RoleSchema = z.enum(ROLES);
export const PermissionSchema = z.enum(PERMISSIONS);

export const EmailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .pipe(z.email());

/**
 * En el login no se aplica la política de longitud mínima (eso solo revela la política);
 * únicamente un máximo para acotar el coste de Argon2id.
 */
export const LoginRequestSchema = z.strictObject({
  email: EmailSchema,
  password: z.string().min(1).max(PASSWORD_MAX_LENGTH),
});
export type LoginRequest = z.infer<typeof LoginRequestSchema>;

export const SessionUserSchema = z.object({
  id: z.uuid(),
  email: z.string(),
  displayName: z.string(),
  role: RoleSchema,
  permissions: z.array(PermissionSchema),
});
export type SessionUser = z.infer<typeof SessionUserSchema>;

/** POST /auth/login → 200. El token CSRF rota al crear la sesión. */
export const LoginResponseSchema = z.object({
  user: SessionUserSchema,
  csrfToken: z.string().min(1),
});
export type LoginResponse = z.infer<typeof LoginResponseSchema>;

/** GET /auth/me → 200 */
export const MeResponseSchema = z.object({ user: SessionUserSchema });
export type MeResponse = z.infer<typeof MeResponseSchema>;

/** GET /auth/csrf → 200 */
export const CsrfResponseSchema = z.object({ csrfToken: z.string().min(1) });
export type CsrfResponse = z.infer<typeof CsrfResponseSchema>;
