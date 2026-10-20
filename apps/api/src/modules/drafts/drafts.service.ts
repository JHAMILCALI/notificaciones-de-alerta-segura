import { Injectable } from '@nestjs/common';
import type { Draft as DraftRow } from '@alertasegura/database';
import type { CreateDraftRequest, Draft } from '@alertasegura/shared';
import { notFound } from '../../common/http/api-exception';
import { PrismaService } from '../../database/prisma.service';

function toDraft(row: DraftRow): Draft {
  return {
    id: row.id,
    title: row.title,
    body: row.body,
    severity: row.severity,
    status: row.status,
    ownerId: row.ownerId,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

@Injectable()
export class DraftsService {
  constructor(private readonly prisma: PrismaService) {}

  async create(dto: CreateDraftRequest, ownerId: string): Promise<Draft> {
    const row = await this.prisma.draft.create({
      data: {
        title: dto.title,
        body: dto.body,
        severity: dto.severity,
        ownerId,
      },
    });
    return toDraft(row);
  }

  async listOwn(ownerId: string): Promise<Draft[]> {
    const rows = await this.prisma.draft.findMany({
      where: { ownerId },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    return rows.map(toDraft);
  }

  /** La propiedad ya la comprobó DraftOwnershipGuard; aquí solo se carga. */
  async getById(id: string): Promise<Draft> {
    const row = await this.prisma.draft.findUnique({ where: { id } });
    if (!row) throw notFound();
    return toDraft(row);
  }
}
