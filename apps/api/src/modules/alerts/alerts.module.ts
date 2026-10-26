import { Module } from '@nestjs/common';
import { SignerModule } from '../signer/signer.module';
import { AlertOwnershipGuard } from './alert-ownership.guard';
import { PublishQuotaService } from './publish-quota.service';
import { AlertStateService } from './alert-state.service';
import { AlertsController } from './alerts.controller';
import { AlertsService } from './alerts.service';
import { SigningService } from './signing.service';

@Module({
  imports: [SignerModule],
  controllers: [AlertsController],
  providers: [
    AlertsService,
    AlertStateService,
    SigningService,
    AlertOwnershipGuard,
    PublishQuotaService,
  ],
  exports: [AlertsService, PublishQuotaService],
})
export class AlertsModule {}
