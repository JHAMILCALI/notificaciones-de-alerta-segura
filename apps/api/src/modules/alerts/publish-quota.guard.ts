import {
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';
import { forbidden } from '../../common/http/api-exception';
import { PrismaService } from '../../database/prisma.service';
import { PublishQuotaService } from './publish-quota.service';

/**
 * Control 7: cuota de publicación. Va el último, después de la propiedad: solo se cuenta contra el emisor
 * dueño del borrador. Es una comprobación previa y barata (evita pedir firmas a quien ya la agotó); la
 * definitiva se repite dentro de la transacción de publicación, con el bloqueo por emisor.
 */
@Injectable()
export class PublishQuotaGuard implements CanActivate {
  constructor(
    private readonly quota: PublishQuotaService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const user = req.auth?.user;
    if (!user) throw forbidden();
    await this.quota.enforce(this.prisma, user.id, req);
    return true;
  }
}
