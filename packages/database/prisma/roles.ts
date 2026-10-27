import path from 'node:path';
import { config } from 'dotenv';
import { applyAppRole, APP_ROLE } from '../src/roles';

// El cwd de pnpm es packages/database; el .env está en la raíz del monorepo.
config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

const MIN_PASSWORD = 16;

async function main(): Promise<void> {
  const ownerUrl = process.env.DATABASE_MIGRATION_URL || process.env.DATABASE_URL;
  if (!ownerUrl) {
    throw new Error('Falta DATABASE_MIGRATION_URL (conexión del propietario) en el .env de la raíz.');
  }
  const password = process.env.APP_DB_PASSWORD;
  if (!password) {
    throw new Error(`APP_DB_PASSWORD no está definida: es la contraseña del rol ${APP_ROLE} (revise el .env).`);
  }
  if (password.length < MIN_PASSWORD) {
    throw new Error(`APP_DB_PASSWORD debe tener al menos ${MIN_PASSWORD} caracteres.`);
  }

  const result = await applyAppRole({ ownerConnectionString: ownerUrl, password });
  console.log(
    `[roles] ${APP_ROLE} ${result.roleCreated ? 'creado' : 'actualizado'} en la base "${result.database}" (contraseña aplicada).`,
  );
  for (const [table, privileges] of Object.entries(result.grants)) {
    console.log(`[roles]   ${table.padEnd(16)} ${privileges.join(', ')}`);
  }
}

main().catch((error: unknown) => {
  console.error('[roles] fallo:', error instanceof Error ? error.message : error);
  process.exit(1);
});
