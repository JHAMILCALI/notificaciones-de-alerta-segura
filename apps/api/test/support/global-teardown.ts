import { Client } from 'pg';

export default async function globalTeardown(): Promise<void> {
  const adminUrl = process.env.TEST_ADMIN_DATABASE_URL;
  const dbName = process.env.TEST_DATABASE_NAME;
  if (!adminUrl || !dbName) return;
  const admin = new Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}
