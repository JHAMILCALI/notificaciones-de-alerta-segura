import {
  Injectable,
  Logger,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import {
  hasPermission,
  type AuditAction,
  type Permission,
} from '@alertasegura/shared';
import { AuditService } from '../../modules/audit/audit.service';
import {
  ANY_ROLE,
  DENIED_ACTION_KEY,
  IS_PUBLIC,
  PERMISSIONS_KEY,
} from '../decorators/metadata';
import { forbidden } from '../http/api-exception';

/** Control 5: RBAC con la matriz `ROLE_PERMISSIONS`. Una ruta sin política declarada se deniega. */
@Injectable()
export class PermissionsGuard implements CanActivate {
  private readonly logger = new Logger(PermissionsGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly audit: AuditService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];
    if (
      this.reflector.getAllAndOverride<boolean | undefined>(IS_PUBLIC, targets)
    )
      return true;

    const req = context.switchToHttp().getRequest<Request>();
    const required = this.reflector.getAllAndOverride<Permission[] | undefined>(
      PERMISSIONS_KEY,
      targets,
    );
    const anyRole = this.reflector.getAllAndOverride<boolean | undefined>(
      ANY_ROLE,
      targets,
    );
    const user = req.auth?.user;
    const route = `${req.method} ${(req.originalUrl ?? '').split('?')[0]}`;

    if (!user) throw forbidden(); // inalcanzable tras AuthenticationGuard; defensa en profundidad

    if (required === undefined) {
      if (anyRole) return true;
      this.logger.error(`Ruta sin política de acceso declarada: ${route}`);
      await this.deny(req, context, { reason: 'no_policy', route });
      throw forbidden();
    }

    if (required.every((permission) => hasPermission(user.role, permission)))
      return true;

    await this.deny(req, context, {
      reason: 'missing_permission',
      required,
      role: user.role,
      route,
    });
    throw forbidden();
  }

  private async deny(
    req: Request,
    context: ExecutionContext,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    const action =
      this.reflector.get<AuditAction | undefined>(
        DENIED_ACTION_KEY,
        context.getHandler(),
      ) ?? 'ACCESS_DENIED';
    await this.audit.record({
      action,
      outcome: 'DENIED',
      actorId: req.auth?.user.id ?? null,
      req,
      metadata,
    });
  }
}
