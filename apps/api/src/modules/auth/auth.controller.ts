import { Controller, Get, HttpCode, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import {
  LoginRequestSchema,
  type CsrfResponse,
  type LoginRequest,
  type LoginResponse,
  type MeResponse,
} from '@alertasegura/shared';
import {
  AnyRole,
  CurrentUser,
  Public,
  QuietUnauthenticated,
  RateLimit,
  Validate,
  ValidBody,
} from '../../common/decorators/metadata';
import type { AuthenticatedUser } from '../../common/http/request-context';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Get('csrf')
  csrf(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): CsrfResponse {
    return this.auth.issueCsrf(req, res);
  }

  @Public()
  @RateLimit('login')
  @Validate({ body: LoginRequestSchema })
  @HttpCode(200)
  @Post('login')
  login(
    @ValidBody() body: unknown,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResponse> {
    return this.auth.login(body as LoginRequest, req, res);
  }

  @AnyRole()
  @HttpCode(204)
  @Post('logout')
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.auth.logout(req, res);
  }

  @AnyRole()
  @QuietUnauthenticated()
  @Get('me')
  me(@CurrentUser() user: AuthenticatedUser): MeResponse {
    return this.auth.me(user);
  }
}
