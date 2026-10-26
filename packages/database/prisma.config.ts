import path from 'node:path';
import { config } from 'dotenv';
import { defineConfig, env } from 'prisma/config';

// El cwd de pnpm es packages/database; el .env vive en la raíz del monorepo.
// En CI/producción las variables ya vienen del entorno y dotenv no las pisa.
// Migraciones y seed usan el rol propietario (DATABASE_MIGRATION_URL); DATABASE_URL es el rol de la app.
config({ path: path.resolve(__dirname, '../../.env'), quiet: true });

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    seed: 'tsx prisma/seed.ts',
  },
  datasource: {
    url: process.env.DATABASE_MIGRATION_URL || env('DATABASE_URL'),
  },
});
