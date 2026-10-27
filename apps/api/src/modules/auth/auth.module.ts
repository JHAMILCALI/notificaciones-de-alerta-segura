import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { CsrfService } from './csrf.service';
import { PasswordService } from './password.service';
import { SessionPurgeService } from './session-purge.service';
import { SessionService } from './session.service';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    SessionService,
    SessionPurgeService,
    CsrfService,
    PasswordService,
  ],
  exports: [SessionService, SessionPurgeService, CsrfService, PasswordService],
})
export class AuthModule {}
