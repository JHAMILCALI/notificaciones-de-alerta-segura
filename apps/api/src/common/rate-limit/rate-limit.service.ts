import {
  Injectable,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import type { Request } from 'express';
import type { RateLimitRule } from '../../config/env';
import { AuditService } from '../../modules/audit/audit.service';
import { rateLimited } from '../http/api-exception';
import {
  SlidingWindowLimiter,
  type LimitResult,
} from './sliding-window-limiter';

export type RateLimitScopeName =
  'global-ip' | 'login-ip' | 'login-account' | 'user';

/** Para no inundar la auditoría, un mismo bloqueo se registra como máximo una vez por minuto. */
const AUDIT_DEDUP_MS = 60_000;

@Injectable()
export class RateLimitService implements OnModuleInit, OnModuleDestroy {
  private readonly limiter = new SlidingWindowLimiter();
  private readonly lastAudited = new Map<string, number>();
  private timer?: NodeJS.Timeout;

  constructor(private readonly audit: AuditService) {}

  onModuleInit(): void {
    this.timer = setInterval(() => {
      const now = Date.now();
      this.limiter.sweep(now);
      for (const [key, at] of this.lastAudited) {
        if (now - at > AUDIT_DEDUP_MS) this.lastAudited.delete(key);
      }
    }, 60_000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /** Consume un cupo; si no hay, audita RATE_LIMITED y responde 429 con Retry-After. */
  async enforce(
    scope: RateLimitScopeName,
    subject: string,
    rule: RateLimitRule,
    req: Request,
    actorId?: string,
  ): Promise<void> {
    const key = `${scope}:${subject}`;
    const result = this.limiter.consume(
      key,
      rule.limit,
      rule.windowSeconds * 1000,
    );
    if (!result.allowed)
      await this.deny(key, scope, rule, result, req, actorId);
  }

  /** Comprueba sin consumir (para contar solo intentos fallidos). */
  async ensureBelow(
    scope: RateLimitScopeName,
    subject: string,
    rule: RateLimitRule,
    req: Request,
  ): Promise<void> {
    const key = `${scope}:${subject}`;
    const result = this.limiter.peek(
      key,
      rule.limit,
      rule.windowSeconds * 1000,
    );
    if (!result.allowed) await this.deny(key, scope, rule, result, req);
  }

  recordFailure(
    scope: RateLimitScopeName,
    subject: string,
    rule: RateLimitRule,
  ): void {
    this.limiter.record(`${scope}:${subject}`, rule.windowSeconds * 1000);
  }

  private async deny(
    key: string,
    scope: RateLimitScopeName,
    rule: RateLimitRule,
    result: LimitResult,
    req: Request,
    actorId?: string,
  ): Promise<never> {
    const now = Date.now();
    const last = this.lastAudited.get(key);
    if (last === undefined || now - last >= AUDIT_DEDUP_MS) {
      this.lastAudited.set(key, now);
      await this.audit.record({
        action: 'RATE_LIMITED',
        outcome: 'DENIED',
        actorId: actorId ?? null,
        targetType: 'rate-limit',
        targetId: scope,
        req,
        metadata: {
          scope,
          limit: rule.limit,
          windowSeconds: rule.windowSeconds,
          retryAfterSeconds: result.retryAfterSeconds,
          route: `${req.method} ${(req.originalUrl ?? '').split('?')[0]}`,
        },
      });
    }
    throw rateLimited(result.retryAfterSeconds);
  }
}
