/**
 * Roles del personal interno. Los ciudadanos consultan de forma anónima y no tienen cuenta.
 * No existe autorregistro. Desde la semana 2 (D-1) los emisores los da de alta el responsable del
 * laboratorio con un comando local auditado, nunca el ADMIN por la API (§03 de la propuesta).
 */
export const ROLES = ['ADMIN', 'ISSUER', 'AUDITOR'] as const;
export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  'users:read',
  'drafts:create',
  'drafts:read-own',
  'alerts:publish',
  'alerts:cancel',
  'audit:read',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

/**
 * Matriz RBAC única. La API la aplica; el frontend solo la usa para mostrar u ocultar
 * elementos y nunca como control de seguridad.
 * ADMIN no publica ni cancela alertas. Publicar y cancelar exigen además ser propietario (emisor_id).
 */
export const ROLE_PERMISSIONS: Readonly<Record<Role, readonly Permission[]>> = {
  ADMIN: ['users:read', 'audit:read'],
  ISSUER: ['drafts:create', 'drafts:read-own', 'alerts:publish', 'alerts:cancel'],
  AUDITOR: ['audit:read'],
};

export function permissionsFor(role: Role): readonly Permission[] {
  return ROLE_PERMISSIONS[role];
}

export function hasPermission(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].includes(permission);
}
