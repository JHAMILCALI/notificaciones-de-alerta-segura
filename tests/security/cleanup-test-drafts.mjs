#!/usr/bin/env node
/**
 * Limpieza específica de los borradores creados por las pruebas automatizadas en la BD de desarrollo.
 *
 * - Por defecto es una simulación: lista lo que borraría y no modifica nada.
 * - Con `--apply` borra, en una transacción, solo los borradores que cumplen TODAS las condiciones de
 *   una firma de `test-data.mjs` (patrón del mensaje y dueño esperado con rol ISSUER) y siguen en DRAFT.
 *   Un borrador publicado nunca se borra: su alerta firmada es inmutable y lo referencia.
 *   Si el número de filas borradas no coincide con el previsto, revierte.
 * - No toca usuarios, sesiones, borradores del seed, alertas publicadas ni la auditoría.
 * - Usa el rol propietario (DATABASE_MIGRATION_URL): el rol de la app no tiene DELETE sobre borradores.
 * - Se niega a ejecutarse contra una base que no esté en localhost.
 *
 * Uso: node tests/security/cleanup-test-drafts.mjs [--apply]
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BROWSER_DRAFT, G1_DRAFT, G2_DRAFT } from './test-data.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const apply = process.argv.includes('--apply');
const env = Object.fromEntries(
  readFileSync(join(root, '.env'), 'utf8')
    .split(/\r?\n/)
    .filter((l) => /^[A-Z0-9_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);

const connectionString = env.DATABASE_MIGRATION_URL || env.DATABASE_URL;
const url = new URL(connectionString);
if (!['localhost', '127.0.0.1', '::1', '[::1]'].includes(url.hostname)) {
  console.error(`Rechazado: la limpieza solo se ejecuta contra una BD local (host=${url.hostname}).`);
  process.exit(2);
}
const seedIssuer = env[BROWSER_DRAFT.ownerEnv]?.trim().toLowerCase();
if (!seedIssuer) {
  console.error(`Falta ${BROWSER_DRAFT.ownerEnv} en .env.`);
  process.exit(2);
}

// pg es dependencia de packages/database; se resuelve desde allí.
const { Client } = createRequire(join(root, 'packages', 'database', 'package.json'))('pg');

// Las mismas condiciones en SQL (para seleccionar y volver a comprobar al borrar) y en JS (para clasificar).
const WHERE = `
  u.role = 'ISSUER' AND d.status = 'DRAFT' AND d."alertaId" IS NULL AND (
    (d.mensaje ~ $1 AND u.email ~ $2)
    OR (d.mensaje ~ $3 AND u.email ~ $4)
    OR (d.mensaje ~ $5 AND u.email = $6)
  )`;
const params = [
  G1_DRAFT.mensajePattern.source,
  G1_DRAFT.ownerPattern.source,
  G2_DRAFT.mensajePattern.source,
  G2_DRAFT.ownerPattern.source,
  BROWSER_DRAFT.mensajePattern.source,
  seedIssuer,
];

function sourceOf(row) {
  if (row.status !== 'DRAFT' || row.alertaId !== null) return null;
  for (const sig of [G1_DRAFT, G2_DRAFT]) {
    if (sig.mensajePattern.test(row.mensaje) && sig.ownerPattern.test(row.email)) return sig.source;
  }
  if (BROWSER_DRAFT.mensajePattern.test(row.mensaje) && row.email === seedIssuer) return BROWSER_DRAFT.source;
  return null;
}

const client = new Client({ connectionString });
await client.connect();
try {
  await client.query('BEGIN');
  const total = (await client.query('SELECT count(*)::int AS n FROM "Draft"')).rows[0].n;
  const { rows } = await client.query(
    `SELECT d.id, d.mensaje, d.status, d."alertaId", u.email, d."createdAt"
       FROM "Draft" d JOIN "User" u ON u.id = d."ownerId"
      WHERE ${WHERE}
      ORDER BY d."createdAt"
      FOR UPDATE OF d`,
    params,
  );
  const candidates = rows.filter((row) => sourceOf(row) !== null);
  if (candidates.length !== rows.length) throw new Error('Discrepancia entre el filtro SQL y el de JS; no se borra nada.');

  console.log(`${apply ? 'LIMPIEZA' : 'SIMULACIÓN (sin --apply no se modifica nada)'} · ${url.host}${url.pathname}`);
  console.log(`Borradores en la BD: ${total} · creados por pruebas automatizadas: ${candidates.length} · se conservan: ${total - candidates.length}`);
  for (const row of candidates) {
    console.log(`  - ${row.id}  "${row.mensaje}"  (${row.email}, ${row.createdAt.toISOString()})  ← ${sourceOf(row)}`);
  }

  if (!apply || candidates.length === 0) {
    await client.query('ROLLBACK');
  } else {
    const ids = candidates.map((row) => row.id);
    const result = await client.query(
      `DELETE FROM "Draft" d USING "User" u
        WHERE u.id = d."ownerId" AND d.id = ANY($7::uuid[]) AND ${WHERE}`,
      [...params, ids],
    );
    if (result.rowCount !== ids.length) {
      throw new Error(`Se esperaban ${ids.length} filas y se borrarían ${result.rowCount}; se revierte.`);
    }
    await client.query('COMMIT');
    const after = (await client.query('SELECT count(*)::int AS n FROM "Draft"')).rows[0].n;
    console.log(`Borrados: ${result.rowCount}. Borradores restantes: ${after}.`);
  }
} catch (error) {
  await client.query('ROLLBACK').catch(() => {});
  console.error(String(error));
  process.exitCode = 1;
} finally {
  await client.end();
}
