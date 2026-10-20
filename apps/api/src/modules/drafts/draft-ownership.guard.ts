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
 * Control 6: autorización por propiedad. El borrador debe existir (404) y pertenecer al usuario
 * autenticado (403). Va después del RBAC: primero se comprueba qué puede hacer el rol y luego
 * sobre qué recurso. Requiere `:draftId` ya validado por ZodValidationGuard.
 */
@Injectable()
export class DraftOwnershipGuard implements CanActivate {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const user = req.auth?.user;
    const params = req.validated?.params as { draftId?: string } | undefined;
    if (!user || !params?.draftId) throw forbidden();

    const draft = await this.prisma.draft.findUnique({
      where: { id: params.draftId },
      select: { id: true, ownerId: true },
    });
    if (!draft) throw notFound();
    if (draft.ownerId === user.id) return true;

    const action =
      this.reflector.get<AuditAction | undefined>(
        DENIED_ACTION_KEY,
        context.getHandler(),
      ) ?? 'ACCESS_DENIED';
    await this.audit.record({
      action,
      outcome: 'DENIED',
      actorId: user.id,
      targetType: 'draft',
      targetId: draft.id,
      req,
      metadata: {
        reason: 'not_owner',
        route: `${req.method} ${(req.originalUrl ?? '').split('?')[0]}`,
      },
    });
    throw forbidden();
  }
}
