import type { CookieOptions } from 'express';
import {
  CSRF_COOKIE,
  SECURE_COOKIE_PREFIX,
  SESSION_COOKIE,
} from '@alertasegura/shared';
import type { AppConfig } from '../../config/env';

export function cookieNames(secure: boolean): {
  session: string;
  csrf: string;
} {
  const prefix = secure ? SECURE_COOKIE_PREFIX : '';
  return {
    session: `${prefix}${SESSION_COOKIE}`,
    csrf: `${prefix}${CSRF_COOKIE}`,
  };
}

/** HttpOnly + SameSite=Strict + Path=/ (+ Secure con HTTPS). Sin Domain: requisito de `__Host-`. */
export function cookieOptions(
  config: AppConfig,
  maxAgeMs?: number,
): CookieOptions {
  const options: CookieOptions = {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.cookieSecure,
    path: '/',
  };
  if (maxAgeMs !== undefined) options.maxAge = maxAgeMs;
  return options;
}

export function clearCookieOptions(config: AppConfig): CookieOptions {
  return cookieOptions(config);
}
