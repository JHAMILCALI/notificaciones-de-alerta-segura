import {
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { APP_CONFIG } from '../../config/config.module';
import type { AppConfig } from '../../config/env';
import { RATE_LIMIT_KEY, type RateLimitScope } from '../decorators/metadata';
import { clientIp } from '../http/request-context';
import { RateLimitService } from '../rate-limit/rate-limit.service';

/** Control 1: límite global por IP y, en el login, el límite de login por IP. */
@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly rateLimit: RateLimitService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const ip = clientIp(req);
    await this.rateLimit.enforce(
      'global-ip',
      ip,
      this.config.rateLimits.global,
      req,
    );
    const scope = this.reflector.get<RateLimitScope | undefined>(
      RATE_LIMIT_KEY,
      context.getHandler(),
    );
    if (scope === 'login') {
      await this.rateLimit.enforce(
        'login-ip',
        ip,
        this.config.rateLimits.loginIp,
        req,
      );
    }
    return true;
  }
}
