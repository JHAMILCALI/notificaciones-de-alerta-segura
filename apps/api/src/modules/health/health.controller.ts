import { Controller, Get, Res } from '@nestjs/common';
import type { Response } from 'express';
import type { HealthResponse } from '@alertasegura/shared';
import { Public } from '../../common/decorators/metadata';
import { PrismaService } from '../../database/prisma.service';

@Controller('health')
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Public()
  @Get()
  async check(
    @Res({ passthrough: true }) res: Response,
  ): Promise<HealthResponse> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return { status: 'ok', database: 'up' };
    } catch {
      res.status(503);
      return { status: 'degraded', database: 'down' };
    }
  }
}
