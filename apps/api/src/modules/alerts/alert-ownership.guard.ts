import {
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import type { AuditAction } from '@alertasegura/shared';
import { DENIED_ACTION_KEY } from '../../common/decorators/metadata';
import { forbidden, notFound } from '../../common/http/api-exception';
import { PrismaService } from '../../database/prisma.service';
import { AuditService } from '../audit/audit.service';

/**
 * Autorización por propiedad de una alerta publicada (P02c): `emisor_id` debe ser el usuario autenticado.
 * Va después del RBAC. Inexistente → 404; de otro emisor → 403 y auditoría (CANCEL_DENIED en la cancelación).
 */
@Injectable()
export class AlertOwnershipGuard implements CanActivate {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const user = req.auth?.user;
    const params = req.validated?.params as { alertaId?: string } | undefined;
    if (!user || !params?.alertaId) throw forbidden();

    const alerta = await this.prisma.alertaPublicada.findUnique({
      where: { id: params.alertaId },
      select: { id: true, emisorId: true },
    });
    if (!alerta) throw notFound();
    if (alerta.emisorId === user.id) return true;

    const action =
      this.reflector.get<AuditAction | undefined>(
        DENIED_ACTION_KEY,
        context.getHandler(),
      ) ?? 'ACCESS_DENIED';
    await this.audit.record({
      action,
      outcome: 'DENIED',
      actorId: user.id,
      targetType: 'alerta',
      targetId: alerta.id,
      req,
      metadata: {
        reason: 'not_owner',
        route: `${req.method} ${(req.originalUrl ?? '').split('?')[0]}`,
      },
    });
    throw forbidden();
  }
}
