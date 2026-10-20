import { Module } from '@nestjs/common';
import { DraftOwnershipGuard } from './draft-ownership.guard';
import { DraftsController } from './drafts.controller';
import { DraftsService } from './drafts.service';

@Module({
  controllers: [DraftsController],
  providers: [DraftsService, DraftOwnershipGuard],
})
export class DraftsModule {}
