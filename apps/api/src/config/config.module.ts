import { Global, Module } from '@nestjs/common';
import { loadConfig, type AppConfig } from './env';

export const APP_CONFIG = Symbol('APP_CONFIG');
export type { AppConfig };

@Global()
@Module({
  providers: [
    { provide: APP_CONFIG, useFactory: (): AppConfig => loadConfig() },
  ],
  exports: [APP_CONFIG],
})
export class ConfigModule {}
