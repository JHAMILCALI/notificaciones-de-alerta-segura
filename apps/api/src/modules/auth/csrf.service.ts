import { Inject, Injectable } from '@nestjs/common';
import {
  hmacBase64Url,
  randomToken,
  safeEqual,
} from '../../common/crypto/tokens';
import { APP_CONFIG } from '../../config/config.module';
import type { AppConfig } from '../../config/env';

/**
 * CSRF "signed double-submit" (OWASP). Token = `<nonce>.<HMAC(CSRF_SECRET, contexto|nonce)>`.
 * El contexto es el id de la sesión (o "anon" antes de iniciar sesión), de modo que un token
 * emitido para otra sesión, o para un anónimo, no vale. El mismo valor viaja en la cookie
 * HttpOnly `as_csrf` y en la cabecera `X-CSRF-Token`; ambos deben coincidir y verificar la firma.
 */
@Injectable()
export class CsrfService {
  constructor(@Inject(APP_CONFIG) private readonly config: AppConfig) {}

  private context(sessionId: string | undefined): string {
    return sessionId ? `session:${sessionId}` : 'anon';
  }

  private sign(nonce: string, sessionId: string | undefined): string {
    return hmacBase64Url(
      this.config.csrfSecret,
      `${this.context(sessionId)}|${nonce}`,
    );
  }

  issue(sessionId?: string): string {
    const nonce = randomToken(24);
    return `${nonce}.${this.sign(nonce, sessionId)}`;
  }

  /** `cookieToken` y `headerToken` pueden venir ausentes o manipulados. */
  verify(
    headerToken: unknown,
    cookieToken: unknown,
    sessionId?: string,
  ): boolean {
    if (typeof headerToken !== 'string' || typeof cookieToken !== 'string')
      return false;
    if (headerToken.length === 0 || headerToken.length > 256) return false;
    if (!safeEqual(headerToken, cookieToken)) return false;
    const parts = headerToken.split('.');
    if (parts.length !== 2) return false;
    const [nonce, mac] = parts as [string, string];
    if (!nonce || !mac) return false;
    return safeEqual(mac, this.sign(nonce, sessionId));
  }
}
