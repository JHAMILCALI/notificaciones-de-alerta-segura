import {
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { AuditService } from '../../modules/audit/audit.service';
import { SessionService } from '../../modules/auth/session.service';
import { APP_CONFIG } from '../../config/config.module';
import type { AppConfig } from '../../config/env';
import { IS_PUBLIC, QUIET_401_KEY } from '../decorators/metadata';
import { unauthenticated } from '../http/api-exception';
import { clearCookieOptions, cookieNames } from '../http/cookies';
import { RateLimitService } from '../rate-limit/rate-limit.service';

/**
 * Control 2: resuelve la sesión de la cookie (en todas las rutas) y exige una válida en las
 * rutas no públicas. Después aplica el límite por usuario autenticado (la clave es el id de
 * usuario, que solo se conoce una vez resuelta la sesión).
 */
@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly sessions: SessionService,
    private readonly audit: AuditService,
    private readonly rateLimit: RateLimitService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(
      IS_PUBLIC,
      [context.getHandler(), context.getClass()],
    );
    const quiet = this.reflector.get<boolean | undefined>(
      QUIET_401_KEY,
      context.getHandler(),
    );
    const names = cookieNames(this.config.cookieSecure);
    const cookies = (req.cookies ?? {}) as Record<string, unknown>;

    const check = await this.sessions.resolve(cookies[names.session]);
    const route = `${req.method} ${(req.originalUrl ?? '').split('?')[0]}`;

    if (check.status === 'valid') {
      req.auth = check.auth;
      await this.rateLimit.enforce(
        'user',
        check.auth.user.id,
        this.config.rateLimits.user,
        req,
        check.auth.user.id,
      );
      return true;
    }

    if (check.status === 'rejected') {
      // La cookie ya no sirve: se borra para que el cliente no la reenvíe y se deja constancia.
      res.clearCookie(names.session, clearCookieOptions(this.config));
      res.clearCookie(names.csrf, clearCookieOptions(this.config));
      await this.audit.record({
        action: 'AUTH_SESSION_REJECTED',
        outcome: 'DENIED',
        req,
        metadata: { reason: check.reason, route },
      });
    } else if (!isPublic && !quiet) {
      await this.audit.record({
        action: 'ACCESS_DENIED',
        outcome: 'DENIED',
        req,
        metadata: { reason: 'unauthenticated', route },
      });
    }

    if (!isPublic) throw unauthenticated();
    return true;
  }
}
