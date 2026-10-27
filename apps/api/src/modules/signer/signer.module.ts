import { Module } from '@nestjs/common';
import { APP_CONFIG, type AppConfig } from '../../config/config.module';
import { HttpSignerClient, SIGNER_CLIENT } from './signer.client';

@Module({
  providers: [
    {
      provide: SIGNER_CLIENT,
      inject: [APP_CONFIG],
      useFactory: (config: AppConfig) =>
        new HttpSignerClient(config.signer.socketPath, config.signer.timeoutMs),
    },
  ],
  exports: [SIGNER_CLIENT],
})
export class SignerModule {}
