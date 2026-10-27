import path from 'node:path';
import { config } from 'dotenv';
import { Client } from 'pg';

// El cwd de pnpm es packages/database; el .env está en la raíz del monorepo.
config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

/**
 * P07 (S2-33): con el rol de la app, UPDATE, DELETE y TRUNCATE sobre las alertas publicadas, los eventos, los
 * estados y la auditoría deben fallar con `permission denied` (SQLSTATE 42501). Se conecta con DATABASE_URL (el
 * rol `alertasegura_app`) y deja en la salida estándar la evidencia: quién es, cuántas filas hay que proteger y
 * el SQLSTATE de cada sentencia. Sale con código 1 si alguna sentencia NO falla con 42501.
 */
const TABLES = ['AlertaPublicada', 'EventoAlerta', 'EstadoAlerta', 'AuditLog'] as const;

/** UPDATE sin cambio real de datos: basta para que PostgreSQL exija el privilegio UPDATE. */
const STATEMENTS: Array<[string, (table: string) => string]> = [
  ['UPDATE', (t) => `UPDATE "${t}" SET "id" = "id"`],
  ['DELETE', (t) => `DELETE FROM "${t}"`],
  ['TRUNCATE', (t) => `TRUNCATE TABLE "${t}"`],
];

async function main(): Promise<void> {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('Falta DATABASE_URL (el rol alertasegura_app) en el .env de la raíz.');

  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    const who = (
      await client.query<{ usr: string; db: string; super: string; now: string }>(
        `SELECT current_user AS usr, current_database() AS db,
                (SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user) AS super,
                to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS now`,
      )
    ).rows[0];
    console.log('P07 — UPDATE/DELETE/TRUNCATE con el rol de la app');
    console.log(`fecha=${who?.now} usuario=${who?.usr} base=${who?.db} superusuario=${who?.super}`);
    console.log('');

    console.log('Filas que hay que proteger (SELECT permitido):');
    for (const table of TABLES) {
      const n = (await client.query<{ n: string }>(`SELECT count(*) AS n FROM "${table}"`)).rows[0]?.n;
      console.log(`  ${table.padEnd(16)} ${n} fila(s)`);
    }
    console.log('');

    console.log(`${'tabla'.padEnd(16)} ${'sentencia'.padEnd(9)} ${'SQLSTATE'.padEnd(8)} mensaje`);
    let failures = 0;
    for (const table of TABLES) {
      for (const [name, build] of STATEMENTS) {
        let code = 'OK';
        let message = 'LA SENTENCIA SE EJECUTÓ';
        try {
          await client.query(build(table));
        } catch (error) {
          const e = error as { code?: string; message?: string };
          code = e.code ?? '?';
          message = e.message ?? String(error);
        }
        if (code !== '42501') failures += 1;
        console.log(`${table.padEnd(16)} ${name.padEnd(9)} ${code.padEnd(8)} ${message}`);
      }
    }

    console.log('');
    console.log(
      failures === 0
        ? 'RESULTADO: 12/12 sentencias rechazadas con 42501 (permission denied). P07 APROBADA.'
        : `RESULTADO: ${failures} sentencia(s) NO fueron rechazadas con 42501. P07 FALLA.`,
    );
    if (failures > 0) process.exitCode = 1;
  } finally {
    await client.end();
  }
}

main().catch((error: unknown) => {
  console.error('[p07] fallo:', error instanceof Error ? error.message : error);
  process.exit(1);
});
