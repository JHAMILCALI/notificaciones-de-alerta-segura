import { Module } from '@nestjs/common';
import { AlertsModule } from '../alerts/alerts.module';
import { DraftOwnershipGuard } from './draft-ownership.guard';
import { DraftsController } from './drafts.controller';
import { DraftsService } from './drafts.service';

@Module({
  imports: [AlertsModule],
  controllers: [DraftsController],
  providers: [DraftsService, DraftOwnershipGuard],
})
export class DraftsModule {}
