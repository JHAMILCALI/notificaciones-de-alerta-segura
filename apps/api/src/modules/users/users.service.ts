import { Injectable } from '@nestjs/common';
import { Role } from '@alertasegura/database';
import type { UserListResponse, UserSummary } from '@alertasegura/shared';
import { PrismaService } from '../../database/prisma.service';

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
  constructor(private readonly prisma: PrismaService) {}

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
}
