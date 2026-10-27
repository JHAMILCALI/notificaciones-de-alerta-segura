import { Inject, Injectable } from '@nestjs/common';
import { UserStatus } from '@alertasegura/database';
import { randomToken, sha256Hex } from '../../common/crypto/tokens';
import type { AuthContext } from '../../common/http/request-context';
import { APP_CONFIG } from '../../config/config.module';
import type { AppConfig } from '../../config/env';
import { PrismaService } from '../../database/prisma.service';

export type SessionRejectionReason =
  | 'malformed'
  | 'unknown'
  | 'revoked'
  | 'expired'
  | 'idle_timeout'
  | 'user_disabled';

export type SessionCheck =
  | { status: 'none' }
  | { status: 'rejected'; reason: SessionRejectionReason }
  | { status: 'valid'; auth: AuthContext };

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/** Actualizar `lastSeenAt` en cada petición escribiría en BD sin necesidad. */
const TOUCH_INTERVAL_MS = 30_000;

@Injectable()
export class SessionService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  async create(userId: string, ip: string | null, userAgent: string | null) {
    const token = randomToken(32);
    const now = new Date();
    const session = await this.prisma.session.create({
      data: {
        tokenHash: sha256Hex(token),
        userId,
        createdAt: now,
        lastSeenAt: now,
        expiresAt: new Date(now.getTime() + this.config.session.absoluteTtlMs),
        ip,
        userAgent,
      },
    });
    return { token, sessionId: session.id, expiresAt: session.expiresAt };
  }

  async resolve(rawToken: unknown, now = new Date()): Promise<SessionCheck> {
    if (rawToken === undefined || rawToken === '') return { status: 'none' };
    if (typeof rawToken !== 'string' || !TOKEN_PATTERN.test(rawToken)) {
      return { status: 'rejected', reason: 'malformed' };
    }
    const session = await this.prisma.session.findUnique({
      where: { tokenHash: sha256Hex(rawToken) },
      include: { user: true },
    });
    if (!session) return { status: 'rejected', reason: 'unknown' };
    if (session.revokedAt) return { status: 'rejected', reason: 'revoked' };
    if (session.expiresAt.getTime() <= now.getTime())
      return { status: 'rejected', reason: 'expired' };
    if (
      now.getTime() - session.lastSeenAt.getTime() >
      this.config.session.idleTtlMs
    ) {
      return { status: 'rejected', reason: 'idle_timeout' };
    }
    if (session.user.status !== UserStatus.ACTIVE) {
      return { status: 'rejected', reason: 'user_disabled' };
    }
    if (now.getTime() - session.lastSeenAt.getTime() > TOUCH_INTERVAL_MS) {
      await this.prisma.session.update({
        where: { id: session.id },
        data: { lastSeenAt: now },
      });
    }
    return {
      status: 'valid',
      auth: {
        sessionId: session.id,
        user: {
          id: session.user.id,
          email: session.user.email,
          displayName: session.user.displayName,
          role: session.user.role,
        },
      },
    };
  }

  /** Idempotente: revocar una sesión ya revocada no cambia su fecha de revocación. */
  async revoke(sessionId: string): Promise<void> {
    await this.prisma.session.updateMany({
      where: { id: sessionId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }
}
