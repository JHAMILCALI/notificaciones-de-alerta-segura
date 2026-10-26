import { Inject, Injectable } from '@nestjs/common';
import type { Request } from 'express';
import type { Prisma } from '@alertasegura/database';
import { rateLimited } from '../../common/http/api-exception';
import { APP_CONFIG, type AppConfig } from '../../config/config.module';
import { PrismaService } from '../../database/prisma.service';
import { AuditService } from '../audit/audit.service';

type Db = Pick<Prisma.TransactionClient, 'alertaPublicada'>;

/**
 * Cuota de publicación por emisor (RATE_PUBLISH_LIMIT por RATE_PUBLISH_WINDOW_SECONDS, por defecto 10 por hora).
 * A diferencia del rate limiting en memoria, cuenta las alertas REALMENTE publicadas en la base: sobrevive a un
 * reinicio, es la misma para todas las instancias y los intentos fallidos (firmante caído, 409) no la consumen.
 */
@Injectable()
export class PublishQuotaService {
  constructor(
    @Inject(APP_CONFIG) private readonly config: AppConfig,
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Serializa las publicaciones de un mismo emisor hasta el fin de la transacción. Sin esto, dos peticiones
   * simultáneas podrían leer "9 de 10" y publicar ambas.
   */
  async lockEmisor(
    tx: Pick<Prisma.TransactionClient, '$executeRaw'>,
    emisorId: string,
  ): Promise<void> {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${emisorId}, 0))`;
  }

  /**
   * Si el emisor ya agotó la cuota: audita RATE_LIMITED y responde 429 con Retry-After (segundos hasta que la
   * publicación más antigua de la ventana la libere).
   */
  async enforce(db: Db, emisorId: string, req: Request): Promise<void> {
    const { limit, windowSeconds } = this.config.rateLimits.publish;
    const windowMs = windowSeconds * 1000;
    // publishedAt lo pone la base con su propio reloj (now()), que coincide con el del proceso.
    const now = Date.now();
    const recent = await db.alertaPublicada.findMany({
      where: { emisorId, publishedAt: { gt: new Date(now - windowMs) } },
      orderBy: { publishedAt: 'desc' },
      take: limit,
      select: { publishedAt: true },
    });
    if (recent.length < limit) return;

    const oldest = recent[recent.length - 1]?.publishedAt.getTime() ?? now;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((oldest + windowMs - now) / 1000),
    );
    await this.audit.record({
      action: 'RATE_LIMITED',
      outcome: 'DENIED',
      actorId: emisorId,
      targetType: 'rate-limit',
      targetId: 'publish-quota',
      req,
      metadata: {
        scope: 'publish-quota',
        limit,
        windowSeconds,
        retryAfterSeconds,
        route: `${req.method} ${(req.originalUrl ?? '').split('?')[0]}`,
      },
    });
    throw rateLimited(retryAfterSeconds);
  }
}
