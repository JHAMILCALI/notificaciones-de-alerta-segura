import {
  SetMetadata,
  createParamDecorator,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';
import type { ZodType } from 'zod';
import type { AuditAction, Permission } from '@alertasegura/shared';
import type { AuthenticatedUser } from '../http/request-context';

export const IS_PUBLIC = 'as:public';
export const ANY_ROLE = 'as:any-role';
export const PERMISSIONS_KEY = 'as:permissions';
export const VALIDATE_KEY = 'as:validate';
export const RATE_LIMIT_KEY = 'as:rate-limit';
export const DENIED_ACTION_KEY = 'as:denied-action';
export const QUIET_401_KEY = 'as:quiet-401';

/** Ruta accesible sin sesión. El resto exige sesión válida (denegación por defecto). */
export const Public = (): MethodDecorator & ClassDecorator =>
  SetMetadata(IS_PUBLIC, true);

/** Ruta para cualquier usuario autenticado, sin permiso específico. */
export const AnyRole = (): MethodDecorator & ClassDecorator =>
  SetMetadata(ANY_ROLE, true);

/** Exige TODOS los permisos indicados (matriz `ROLE_PERMISSIONS` de shared). */
export const RequirePermissions = (
  ...permissions: Permission[]
): MethodDecorator & ClassDecorator =>
  SetMetadata(PERMISSIONS_KEY, permissions);

export interface ValidationSchemas {
  body?: ZodType;
  params?: ZodType;
  query?: ZodType;
}
export const Validate = (schemas: ValidationSchemas): MethodDecorator =>
  SetMetadata(VALIDATE_KEY, schemas);

/** Límite adicional por IP específico de la ruta (login). */
export type RateLimitScope = 'login';
export const RateLimit = (scope: RateLimitScope): MethodDecorator =>
  SetMetadata(RATE_LIMIT_KEY, scope);

/** Acción de auditoría para denegaciones 403 de la ruta (por defecto ACCESS_DENIED). */
export const DeniedAction = (action: AuditAction): MethodDecorator =>
  SetMetadata(DENIED_ACTION_KEY, action);

/** No audita el 401 de esta ruta (p. ej. /auth/me, que la PWA consulta siendo anónima). */
export const QuietUnauthenticated = (): MethodDecorator =>
  SetMetadata(QUIET_401_KEY, true);

export const CurrentUser = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): AuthenticatedUser => {
    const req = ctx.switchToHttp().getRequest<Request>();
    if (!req.auth)
      throw new Error('CurrentUser usado en una ruta sin autenticación');
    return req.auth.user;
  },
);

export const ValidBody = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): unknown =>
    ctx.switchToHttp().getRequest<Request>().validated?.body,
);
export const ValidParams = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): unknown =>
    ctx.switchToHttp().getRequest<Request>().validated?.params,
);
export const ValidQuery = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): unknown =>
    ctx.switchToHttp().getRequest<Request>().validated?.query,
);
