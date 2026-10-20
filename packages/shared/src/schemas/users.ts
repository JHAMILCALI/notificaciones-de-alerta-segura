import { z } from 'zod';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '../constants/http.js';
import { EmailSchema, RoleSchema } from './auth.js';

export const PasswordSchema = z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH);

export const DisplayNameSchema = z.string().trim().min(2).max(100);

/** POST /admin/issuers (solo ADMIN). El rol ISSUER lo fija el servidor, no el cliente. */
export const ProvisionIssuerRequestSchema = z.strictObject({
  email: EmailSchema,
  displayName: DisplayNameSchema,
  password: PasswordSchema,
});
export type ProvisionIssuerRequest = z.infer<typeof ProvisionIssuerRequestSchema>;

export const UserStatusSchema = z.enum(['ACTIVE', 'DISABLED']);

export const UserSummarySchema = z.object({
  id: z.uuid(),
  email: z.string(),
  displayName: z.string(),
  role: RoleSchema,
  status: UserStatusSchema,
  createdAt: z.iso.datetime(),
});
export type UserSummary = z.infer<typeof UserSummarySchema>;

/** POST /admin/issuers → 201 */
export const ProvisionIssuerResponseSchema = z.object({ user: UserSummarySchema });

/** GET /admin/users → 200 */
export const UserListResponseSchema = z.object({ users: z.array(UserSummarySchema) });
export type UserListResponse = z.infer<typeof UserListResponseSchema>;
