import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from './generated/client';

export { PrismaClient, Prisma } from './generated/client';
export type {
  User,
  Session,
  Draft,
  AuditLog,
} from './generated/client';
export {
  Role,
  UserStatus,
  TipoAlerta,
  Departamento,
  NivelAlerta,
  DraftStatus,
  AuditOutcome,
} from './generated/enums';
export { ARGON2_OPTIONS, hashPassword, verifyPassword } from './password';

export interface CreatePrismaClientOptions {
  connectionString: string;
  /** Tamaño máximo del pool de `pg` (por defecto 10). */
  maxConnections?: number;
}

/** Adaptador nativo `pg` de Prisma 7 (no hay motor binario de consultas). */
export function createPrismaAdapter(options: CreatePrismaClientOptions): PrismaPg {
  return new PrismaPg({
    connectionString: options.connectionString,
    max: options.maxConnections ?? 10,
  });
}

export function createPrismaClient(options: CreatePrismaClientOptions): PrismaClient {
  return new PrismaClient({ adapter: createPrismaAdapter(options) });
}
