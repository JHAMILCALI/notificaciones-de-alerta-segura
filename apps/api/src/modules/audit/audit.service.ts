import { Injectable, Logger } from '@nestjs/common';
import type { Request } from 'express';
import { AuditOutcome, Prisma } from '@alertasegura/database';
import type {
  AuditAction,
  AuditEntry,
  AuditOutcome as AuditOutcomeValue,
} from '@alertasegura/shared';
import { PrismaService } from '../../database/prisma.service';
import { clientIp, userAgentOf } from '../../common/http/request-context';

const FORBIDDEN_KEY =
  /pass(word)?|token|cookie|secret|authorization|hash|csrf/i;
const MAX_DEPTH = 4;

/** Elimina cualquier clave que pueda contener credenciales; el metadata nunca debe llevarlas. */
export function sanitizeMetadata(
  value: unknown,
  depth = 0,
): Prisma.InputJsonValue {
  if (value === null || value === undefined) return {};
  if (typeof value === 'string') return value.slice(0, 500);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth >= MAX_DEPTH) return '[truncado]';
  if (Array.isArray(value)) {
    return value
      .slice(0, 50)
      .map((item) => sanitizeMetadata(item, depth + 1) ?? null);
  }
  if (typeof value === 'object') {
    const out: Record<string, Prisma.InputJsonValue> = {};
    for (const [key, inner] of Object.entries(
      value as Record<string, unknown>,
    )) {
      if (FORBIDDEN_KEY.test(key)) continue;
      out[key] = sanitizeMetadata(inner, depth + 1);
    }
    return out;
  }
  // Solo pueden llegar bigint, symbol o function: nunca se serializan objetos arbitrarios.
  return typeof value === 'bigint' ? value.toString() : '[no serializable]';
}

export interface AuditRecord {
  action: AuditAction;
  outcome: AuditOutcomeValue;
  actorId?: string | null;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown>;
  /** Petición de origen: de ella se toman IP y user-agent. */
  req?: Request;
  ip?: string | null;
  userAgent?: string | null;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Registra un evento. Si la escritura falla, el error va al log del proceso y la petición
   * continúa (la auditoría no debe tumbar el servicio), pero nunca se silencia.
   */
  async record(entry: AuditRecord): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          action: entry.action,
          outcome: AuditOutcome[entry.outcome],
          actorId: entry.actorId ?? null,
          targetType: entry.targetType ?? null,
          targetId: entry.targetId ?? null,
          ip: entry.ip ?? (entry.req ? clientIp(entry.req) : null),
          userAgent:
            entry.userAgent ?? (entry.req ? userAgentOf(entry.req) : null),
          metadata: sanitizeMetadata(
            entry.metadata ?? {},
          ) as Prisma.InputJsonObject,
        },
      });
    } catch (error) {
      this.logger.error(
        `FALLO DE AUDITORIA action=${entry.action} outcome=${entry.outcome} actor=${entry.actorId ?? '-'}: ` +
          (error instanceof Error ? error.message : 'error desconocido'),
      );
    }
  }

  async list(limit: number): Promise<AuditEntry[]> {
    const rows = await this.prisma.auditLog.findMany({
      orderBy: [{ occurredAt: 'desc' }, { id: 'desc' }],
      take: limit,
    });
    return rows.map((row) => ({
      id: row.id,
      occurredAt: row.occurredAt.toISOString(),
      action: row.action as AuditAction,
      outcome: row.outcome,
      actorId: row.actorId,
      targetType: row.targetType,
      targetId: row.targetId,
      ip: row.ip,
      metadata: (row.metadata ?? {}) as Record<string, unknown>,
    }));
  }
}
