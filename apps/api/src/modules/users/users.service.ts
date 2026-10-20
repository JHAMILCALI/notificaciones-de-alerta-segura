import { Injectable } from '@nestjs/common';
import { Prisma, Role } from '@alertasegura/database';
import type {
  ProvisionIssuerRequest,
  UserListResponse,
  UserSummary,
} from '@alertasegura/shared';
import { conflict } from '../../common/http/api-exception';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { PrismaService } from '../../database/prisma.service';
import { PasswordService } from '../auth/password.service';

interface UserRow {
  id: string;
  email: string;
  displayName: string;
  role: Role;
  status: 'ACTIVE' | 'DISABLED';
  createdAt: Date;
}

function toSummary(row: UserRow): UserSummary {
  return {
    id: row.id,
    email: row.email,
    displayName: row.displayName,
    role: row.role,
    status: row.status,
    createdAt: row.createdAt.toISOString(),
  };
}

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwords: PasswordService,
  ) {}

  async list(): Promise<UserListResponse> {
    const rows = await this.prisma.user.findMany({
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        email: true,
        displayName: true,
        role: true,
        status: true,
        createdAt: true,
      },
    });
    return { users: rows.map(toSummary) };
  }

  /** El rol ISSUER lo fija el servidor; el cliente no puede elegirlo. */
  async provisionIssuer(
    dto: ProvisionIssuerRequest,
    admin: AuthenticatedUser,
  ): Promise<UserSummary> {
    const passwordHash = await this.passwords.hash(dto.password);
    try {
      const row = await this.prisma.user.create({
        data: {
          email: dto.email,
          displayName: dto.displayName,
          passwordHash,
          role: Role.ISSUER,
          createdById: admin.id,
        },
        select: {
          id: true,
          email: true,
          displayName: true,
          role: true,
          status: true,
          createdAt: true,
        },
      });
      return toSummary(row);
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw conflict('Ya existe una cuenta con ese correo');
      }
      throw error;
    }
  }
}
