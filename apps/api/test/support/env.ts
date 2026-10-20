import { existsSync } from 'node:fs';
import path from 'node:path';

/** Carga el .env de la raíz del monorepo sin pisar variables ya definidas (CI). */
export function loadRootEnv(): void {
  const file = path.resolve(__dirname, '../../../../.env');
  if (existsSync(file)) process.loadEnvFile(file);
}
