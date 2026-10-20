import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { Client } from 'pg';
import { loadRootEnv } from './env';

/**
 * Crea una base PostgreSQL aislada y efímera (mismo servidor que DATABASE_URL), le aplica las
 * migraciones reales con `prisma migrate deploy` y la expone en TEST_DATABASE_URL.
 */
export default async function globalSetup(): Promise<void> {
  loadRootEnv();
  const base = process.env.DATABASE_URL;
  if (!base)
    throw new Error(
      'DATABASE_URL no definida: cree el .env en la raíz (ver .env.example).',
    );

  const dbName = `alertasegura_test_${randomBytes(6).toString('hex')}`;
  const adminUrl = new URL(base);
  adminUrl.pathname = '/postgres';
  const testUrl = new URL(base);
  testUrl.pathname = `/${dbName}`;

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
    env: { ...process.env, DATABASE_URL: testUrl.toString() },
    stdio: 'pipe',
  });

  process.env.TEST_DATABASE_URL = testUrl.toString();
  process.env.TEST_ADMIN_DATABASE_URL = adminUrl.toString();
  process.env.TEST_DATABASE_NAME = dbName;
}
