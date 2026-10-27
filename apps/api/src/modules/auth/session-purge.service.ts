import {
  Inject,
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { APP_CONFIG } from '../../config/config.module';
import type { AppConfig } from '../../config/env';
import { PrismaService } from '../../database/prisma.service';

/** Una sesión revocada se conserva este tiempo (útil para investigar un incidente) y luego se borra. */
export const REVOKED_RETENTION_MS = 24 * 3600_000;

/**
 * Purga de sesiones (S2-48). La tabla `Session` solo crece: cada login añade una fila y nada la quita. Esta tarea
 * borra, al arrancar y cada SESSION_PURGE_INTERVAL_MINUTES, las que ya no pueden autenticar a nadie:
 * caducadas (absoluta), inactivas más allá del límite de inactividad y revocadas hace más de 24 h. El rol de la
 * app tiene DELETE solo en `Session`; la auditoría y las alertas no se tocan.
 */
@Injectable()
export class SessionPurgeService
  implements OnApplicationBootstrap, OnModuleDestroy
{
  private readonly logger = new Logger(SessionPurgeService.name);
  private timer: NodeJS.Timeout | undefined;

  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.safePurge();
    this.timer = setInterval(() => {
      void this.safePurge();
    }, this.config.session.purgeIntervalMs);
    this.timer.unref(); // no mantiene vivo el proceso
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /** Borra las sesiones inservibles y devuelve cuántas. `now` solo se inyecta en las pruebas. */
  async purgeExpired(now: Date = new Date()): Promise<number> {
    const { idleTtlMs } = this.config.session;
    const result = await this.prisma.session.deleteMany({
      where: {
        OR: [
          { expiresAt: { lte: now } },
          { lastSeenAt: { lt: new Date(now.getTime() - idleTtlMs) } },
          { revokedAt: { lt: new Date(now.getTime() - REVOKED_RETENTION_MS) } },
        ],
      },
    });
    return result.count;
  }

  /** Una purga fallida se registra y se reintenta en el siguiente ciclo; nunca tumba la API. */
  private async safePurge(): Promise<void> {
    try {
      const count = await this.purgeExpired();
      if (count > 0) this.logger.log(`Sesiones purgadas: ${count}`);
    } catch (error) {
      this.logger.error(
        `Falló la purga de sesiones: ${
          error instanceof Error ? error.message : 'error desconocido'
        }`,
      );
    }
  }
}
