import 'reflect-metadata';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { configureApp } from './app.setup';
import { AppModule } from './app.module';
import { APP_CONFIG } from './config/config.module';
import {
  ConfigError,
  loadConfig,
  loadRootEnvFile,
  type AppConfig,
} from './config/env';

async function bootstrap(): Promise<void> {
  loadRootEnvFile();
  try {
    loadConfig(); // falla rápido, antes de crear nada, con un mensaje claro y sin valores
  } catch (error) {
    if (error instanceof ConfigError) {
      console.error(error.message);
      process.exit(1);
    }
    throw error;
  }

  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: ['log', 'warn', 'error'],
  });
  await configureApp(app);
  const config = app.get<AppConfig>(APP_CONFIG);
  await app.listen(config.port);
  new Logger('Bootstrap').log(
    `API escuchando en el puerto ${config.port} (/api/v1)`,
  );
}

void bootstrap();
