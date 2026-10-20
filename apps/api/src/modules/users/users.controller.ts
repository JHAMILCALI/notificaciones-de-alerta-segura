import { Controller, Get, Post, Req } from '@nestjs/common';
import type { Request } from 'express';
import {
  ProvisionIssuerRequestSchema,
  type ProvisionIssuerRequest,
  type UserListResponse,
} from '@alertasegura/shared';
import {
  CurrentUser,
  RequirePermissions,
  Validate,
  ValidBody,
} from '../../common/decorators/metadata';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { AuditService } from '../audit/audit.service';
import { UsersService } from './users.service';

@Controller('admin')
export class UsersController {
  constructor(
    private readonly users: UsersService,
    private readonly audit: AuditService,
  ) {}

  @RequirePermissions('users:read')
  @Get('users')
  list(): Promise<UserListResponse> {
    return this.users.list();
  }

  @RequirePermissions('issuers:provision')
  @Validate({ body: ProvisionIssuerRequestSchema })
  @Post('issuers')
  async provision(
    @ValidBody() body: unknown,
    @CurrentUser() admin: AuthenticatedUser,
    @Req() req: Request,
  ): Promise<{ user: Awaited<ReturnType<UsersService['provisionIssuer']>> }> {
    const user = await this.users.provisionIssuer(
      body as ProvisionIssuerRequest,
      admin,
    );
    await this.audit.record({
      action: 'ISSUER_PROVISIONED',
      outcome: 'SUCCESS',
      actorId: admin.id,
      targetType: 'user',
      targetId: user.id,
      req,
      metadata: { email: user.email, role: user.role },
    });
    return { user };
  }
}
