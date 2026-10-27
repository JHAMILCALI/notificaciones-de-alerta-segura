import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { Client } from 'pg';
import { applyAppRole, APP_ROLE } from '@alertasegura/database';
import { loadRootEnv } from './env';

/**
 * Crea una base PostgreSQL aislada y efímera (mismo servidor que la conexión del propietario), le aplica
 * las migraciones reales con `prisma migrate deploy` y le concede al rol de la app sus permisos reales
 * (`applyAppRole`, el mismo código de `pnpm db:roles`).
 *
 * - TEST_DATABASE_URL: la base de prueba con el rol `alertasegura_app`. La API de las pruebas corre así,
 *   igual que en producción: lo que el rol no puede hacer, la API tampoco.
 * - TEST_OWNER_DATABASE_URL: la misma base con el propietario (preparar datos y comprobar los triggers).
 */
export default async function globalSetup(): Promise<void> {
  loadRootEnv();
  const base = process.env.DATABASE_MIGRATION_URL || process.env.DATABASE_URL;
  if (!base)
    throw new Error(
      'DATABASE_MIGRATION_URL no definida: cree el .env en la raíz (ver .env.example).',
    );
  const appPassword = process.env.APP_DB_PASSWORD;
  if (!appPassword)
    throw new Error(
      `APP_DB_PASSWORD no definida: las pruebas corren con el rol ${APP_ROLE} (ver .env.example).`,
    );

  const dbName = `alertasegura_test_${randomBytes(6).toString('hex')}`;
  const adminUrl = new URL(base);
  adminUrl.pathname = '/postgres';
  const ownerTestUrl = new URL(base);
  ownerTestUrl.pathname = `/${dbName}`;
  const appTestUrl = new URL(ownerTestUrl);
  appTestUrl.username = APP_ROLE;
  appTestUrl.password = appPassword;

  const admin = new Client({ connectionString: adminUrl.toString() });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE "${dbName}"`);
  } finally {
    await admin.end();
  }

  const databaseDir = path.resolve(__dirname, '../../../../packages/database');
  const prismaCli = require.resolve('prisma/build/index.js', {
    paths: [databaseDir],
  });
  execFileSync(process.execPath, [prismaCli, 'migrate', 'deploy'], {
    cwd: databaseDir,
    env: {
      ...process.env,
      DATABASE_URL: ownerTestUrl.toString(),
      DATABASE_MIGRATION_URL: ownerTestUrl.toString(),
    },
    stdio: 'pipe',
  });
  await applyAppRole({
    ownerConnectionString: ownerTestUrl.toString(),
    password: appPassword,
  });

  process.env.TEST_DATABASE_URL = appTestUrl.toString();
  process.env.TEST_OWNER_DATABASE_URL = ownerTestUrl.toString();
  process.env.TEST_ADMIN_DATABASE_URL = adminUrl.toString();
  process.env.TEST_DATABASE_NAME = dbName;
}
