import { Controller, Get } from '@nestjs/common';
import { AuditQuerySchema, type AuditListResponse } from '@alertasegura/shared';
import {
  RequirePermissions,
  Validate,
  ValidQuery,
} from '../../common/decorators/metadata';
import { AuditService } from './audit.service';

@Controller('audit')
export class AuditController {
  constructor(private readonly audit: AuditService) {}

  @RequirePermissions('audit:read')
  @Validate({ query: AuditQuerySchema })
  @Get()
  async list(@ValidQuery() query: unknown): Promise<AuditListResponse> {
    const { limit } = query as { limit: number };
    return { entries: await this.audit.list(limit) };
  }
}
