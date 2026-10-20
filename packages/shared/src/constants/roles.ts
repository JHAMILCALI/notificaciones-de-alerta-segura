/**
 * Roles del personal interno. Los ciudadanos consultan de forma anónima y no tienen cuenta.
 * No existe autorregistro: ADMIN provisiona a los emisores (separación de funciones).
 */
export const ROLES = ['ADMIN', 'ISSUER', 'AUDITOR'] as const;
export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  'users:read',
  'issuers:provision',
  'drafts:create',
  'drafts:read-own',
  'alerts:publish',
  'audit:read',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

/**
 * Matriz RBAC única. La API la aplica; el frontend solo la usa para mostrar u ocultar
 * elementos y nunca como control de seguridad.
 * ADMIN no publica alertas: gestiona cuentas. Publicar exige además ser propietario del borrador.
 */
export const ROLE_PERMISSIONS: Readonly<Record<Role, readonly Permission[]>> = {
  ADMIN: ['users:read', 'issuers:provision', 'audit:read'],
  ISSUER: ['drafts:create', 'drafts:read-own', 'alerts:publish'],
  AUDITOR: ['audit:read'],
};

export function permissionsFor(role: Role): readonly Permission[] {
  return ROLE_PERMISSIONS[role];
}

export function hasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}
