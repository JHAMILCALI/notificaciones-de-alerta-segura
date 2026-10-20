/** Prefijo global de la API. En desarrollo Vite redirige `/api` a NestJS (mismo origen). */
export const API_PREFIX = '/api/v1';

/** Cabecera en la que el cliente devuelve el token CSRF en métodos no seguros. */
export const CSRF_HEADER = 'x-csrf-token';

/**
 * Nombres de cookie. Con COOKIE_SECURE=true la API usa el prefijo `__Host-`,
 * que obliga a Secure, Path=/ y ausencia de Domain.
 */
export const SESSION_COOKIE = 'as_session';
export const CSRF_COOKIE = 'as_csrf';
export const SECURE_COOKIE_PREFIX = '__Host-';

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;
