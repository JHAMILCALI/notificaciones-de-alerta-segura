import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { AllExceptionsFilter } from './common/filters/all-exceptions.filter';
import { AuthenticationGuard } from './common/guards/authentication.guard';
import { CsrfGuard } from './common/guards/csrf.guard';
import { PermissionsGuard } from './common/guards/permissions.guard';
import { RateLimitGuard } from './common/guards/rate-limit.guard';
import { ZodValidationGuard } from './common/guards/validation.guard';
import { RateLimitModule } from './common/rate-limit/rate-limit.module';
import { ConfigModule } from './config/config.module';
import { DatabaseModule } from './database/database.module';
import { AuditModule } from './modules/audit/audit.module';
import { AuthModule } from './modules/auth/auth.module';
import { ClockModule } from './common/clock/clock';
import { AlertsModule } from './modules/alerts/alerts.module';
import { DraftsModule } from './modules/drafts/drafts.module';
import { HealthModule } from './modules/health/health.module';
import { TrustModule } from './modules/trust/trust.module';
import { UsersModule } from './modules/users/users.module';

@Module({
  imports: [
    ConfigModule,
    ClockModule,
    DatabaseModule,
    RateLimitModule,
    AuditModule,
    AuthModule,
    UsersModule,
    DraftsModule,
    AlertsModule,
    TrustModule,
    HealthModule,
  ],
  providers: [
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
    // El ORDEN de los guards globales ES el orden de controles del contrato:
    // 1 rate limiting -> 2 autenticación -> 3 CSRF -> 4 validación -> 5 RBAC
    // (6, la propiedad, es un guard de ruta que Nest ejecuta después de los globales).
    { provide: APP_GUARD, useClass: RateLimitGuard },
    { provide: APP_GUARD, useClass: AuthenticationGuard },
    { provide: APP_GUARD, useClass: CsrfGuard },
    { provide: APP_GUARD, useClass: ZodValidationGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
  ],
})
export class AppModule {}
