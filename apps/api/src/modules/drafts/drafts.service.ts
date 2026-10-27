import { Injectable } from '@nestjs/common';
import type { Draft as DraftRow } from '@alertasegura/database';
import type { CreateDraftRequest, Draft } from '@alertasegura/shared';
import { notFound } from '../../common/http/api-exception';
import { PrismaService } from '../../database/prisma.service';

function toDraft(row: DraftRow): Draft {
  return {
    id: row.id,
    tipo: row.tipo,
    zona: { departamento: row.departamento, municipio: row.municipio },
    severidad: row.severidad,
    mensaje: row.mensaje,
    vigenciaHoras: row.vigenciaHoras,
    status: row.status,
    ownerId: row.ownerId,
    alertaId: row.alertaId,
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
        tipo: dto.tipo,
        departamento: dto.zona.departamento,
        municipio: dto.zona.municipio,
        severidad: dto.severidad,
        mensaje: dto.mensaje,
        vigenciaHoras: dto.vigenciaHoras,
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
