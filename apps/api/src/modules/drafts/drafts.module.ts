import { Module } from '@nestjs/common';
import { AlertsModule } from '../alerts/alerts.module';
import { PublishQuotaGuard } from '../alerts/publish-quota.guard';
import { DraftOwnershipGuard } from './draft-ownership.guard';
import { DraftsController } from './drafts.controller';
import { DraftsService } from './drafts.service';

@Module({
  imports: [AlertsModule],
  controllers: [DraftsController],
  providers: [DraftsService, DraftOwnershipGuard, PublishQuotaGuard],
})
export class DraftsModule {}
