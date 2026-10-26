import { Controller, Get } from '@nestjs/common';
import type { UserListResponse } from '@alertasegura/shared';
import { RequirePermissions } from '../../common/decorators/metadata';
import { UsersService } from './users.service';

/**
 * D-1: no hay alta de emisores por HTTP (`POST /admin/issuers` → 404). Las cuentas ISSUER las crea
 * el comando de laboratorio `pnpm --filter @alertasegura/database lab issuer:add`.
 */
@Controller('admin')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @RequirePermissions('users:read')
  @Get('users')
  list(): Promise<UserListResponse> {
    return this.users.list();
  }
}
