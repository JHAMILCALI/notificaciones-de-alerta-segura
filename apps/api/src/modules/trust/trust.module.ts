import { Module } from '@nestjs/common';
import { KeyInventoryService } from './key-inventory.service';
import { TrustController } from './trust.controller';
import { TrustService } from './trust.service';

@Module({
  controllers: [TrustController],
  providers: [TrustService, KeyInventoryService],
})
export class TrustModule {}
