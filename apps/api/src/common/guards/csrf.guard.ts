import {
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';
import { CSRF_HEADER } from '@alertasegura/shared';
import { AuditService } from '../../modules/audit/audit.service';
import { CsrfService } from '../../modules/auth/csrf.service';
import { APP_CONFIG } from '../../config/config.module';
import type { AppConfig } from '../../config/env';
import { csrfInvalid } from '../http/api-exception';
import { cookieNames } from '../http/cookies';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Control 3: en métodos no seguros comprueba el `Origin` (si viene) y el token CSRF firmado,
 * ligado a la sesión actual o, sin sesión, al contexto anónimo (login).
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(
    private readonly csrf: CsrfService,
    private readonly audit: AuditService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    if (SAFE_METHODS.has(req.method)) return true;

    const reason = this.check(req);
    if (reason === null) return true;

    await this.audit.record({
      action: 'CSRF_REJECTED',
      outcome: 'DENIED',
      actorId: req.auth?.user.id ?? null,
      req,
      metadata: {
        reason,
        route: `${req.method} ${(req.originalUrl ?? '').split('?')[0]}`,
      },
    });
    throw csrfInvalid();
  }

  private check(req: Request): string | null {
    const origin = req.headers.origin;
    if (origin !== undefined && origin !== this.config.webOrigin)
      return 'origin_mismatch';

    const names = cookieNames(this.config.cookieSecure);
    const cookies = (req.cookies ?? {}) as Record<string, unknown>;
    const header = req.headers[CSRF_HEADER];
    const cookieToken = cookies[names.csrf];
    if (typeof header !== 'string' || typeof cookieToken !== 'string')
      return 'token_missing';
    return this.csrf.verify(header, cookieToken, req.auth?.sessionId)
      ? null
      : 'token_invalid';
  }
}
