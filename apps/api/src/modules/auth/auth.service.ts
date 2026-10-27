import { Inject, Injectable } from '@nestjs/common';
import type { Request, Response } from 'express';
import { UserStatus } from '@alertasegura/database';
import {
  permissionsFor,
  type CsrfResponse,
  type LoginRequest,
  type LoginResponse,
  type MeResponse,
  type SessionUser,
} from '@alertasegura/shared';
import { invalidCredentials } from '../../common/http/api-exception';
import {
  clearCookieOptions,
  cookieNames,
  cookieOptions,
} from '../../common/http/cookies';
import {
  clientIp,
  userAgentOf,
  type AuthenticatedUser,
} from '../../common/http/request-context';
import { RateLimitService } from '../../common/rate-limit/rate-limit.service';
import { APP_CONFIG } from '../../config/config.module';
import type { AppConfig } from '../../config/env';
import { PrismaService } from '../../database/prisma.service';
import { AuditService } from '../audit/audit.service';
import { CsrfService } from './csrf.service';
import { PasswordService } from './password.service';
import { SessionService } from './session.service';

export function toSessionUser(user: AuthenticatedUser): SessionUser {
  return {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    role: user.role,
    permissions: [...permissionsFor(user.role)],
  };
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwords: PasswordService,
    private readonly sessions: SessionService,
    private readonly csrf: CsrfService,
    private readonly audit: AuditService,
    private readonly rateLimit: RateLimitService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async login(
    dto: LoginRequest,
    req: Request,
    res: Response,
  ): Promise<LoginResponse> {
    const { email, password } = dto; // el esquema ya normalizó el correo
    const accountRule = this.config.rateLimits.loginAccount;

    // Límite por cuenta: solo cuentan los intentos fallidos; con el cupo agotado ni se verifica.
    await this.rateLimit.ensureBelow('login-account', email, accountRule, req);

    const user = await this.prisma.user.findUnique({ where: { email } });
    // Se verifica siempre (contra un señuelo si no existe) para igualar tiempos de respuesta.
    const passwordOk = await this.passwords.verify(
      user?.passwordHash ?? null,
      password,
    );

    if (!user || !passwordOk || user.status !== UserStatus.ACTIVE) {
      this.rateLimit.recordFailure('login-account', email, accountRule);
      await this.audit.record({
        action: 'AUTH_LOGIN_FAILED',
        outcome: 'FAILURE',
        actorId: user?.id ?? null,
        targetType: 'account',
        req,
        metadata: {
          email,
          reason: !user
            ? 'unknown_account'
            : !passwordOk
              ? 'bad_password'
              : 'account_disabled',
        },
      });
      throw invalidCredentials();
    }

    // Rotación: si el navegador ya traía una sesión válida, se revoca antes de emitir la nueva.
    if (req.auth) await this.sessions.revoke(req.auth.sessionId);

    const created = await this.sessions.create(
      user.id,
      clientIp(req),
      userAgentOf(req),
    );
    const names = cookieNames(this.config.cookieSecure);
    const csrfToken = this.csrf.issue(created.sessionId);
    res.cookie(
      names.session,
      created.token,
      cookieOptions(this.config, this.config.session.absoluteTtlMs),
    );
    res.cookie(
      names.csrf,
      csrfToken,
      cookieOptions(this.config, this.config.session.absoluteTtlMs),
    );

    await this.audit.record({
      action: 'AUTH_LOGIN_SUCCEEDED',
      outcome: 'SUCCESS',
      actorId: user.id,
      targetType: 'session',
      targetId: created.sessionId,
      req,
      metadata: { rotatedPreviousSession: req.auth !== undefined },
    });

    return {
      user: toSessionUser({
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        role: user.role,
      }),
      csrfToken,
    };
  }

  async logout(req: Request, res: Response): Promise<void> {
    const auth = req.auth;
    if (auth) {
      await this.sessions.revoke(auth.sessionId);
      await this.audit.record({
        action: 'AUTH_LOGOUT',
        outcome: 'SUCCESS',
        actorId: auth.user.id,
        targetType: 'session',
        targetId: auth.sessionId,
        req,
      });
    }
    const names = cookieNames(this.config.cookieSecure);
    res.clearCookie(names.session, clearCookieOptions(this.config));
    res.clearCookie(names.csrf, clearCookieOptions(this.config));
  }

  me(user: AuthenticatedUser): MeResponse {
    return { user: toSessionUser(user) };
  }

  /** Emite un token CSRF para el contexto actual (sesión o anónimo) y fija su cookie. */
  issueCsrf(req: Request, res: Response): CsrfResponse {
    const csrfToken = this.csrf.issue(req.auth?.sessionId);
    const names = cookieNames(this.config.cookieSecure);
    res.cookie(
      names.csrf,
      csrfToken,
      cookieOptions(this.config, this.config.session.absoluteTtlMs),
    );
    return { csrfToken };
  }
}
