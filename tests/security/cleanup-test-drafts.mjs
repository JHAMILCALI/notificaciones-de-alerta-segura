#!/usr/bin/env node
/**
 * Limpieza específica de los borradores creados por las pruebas automatizadas en la BD de desarrollo.
 *
 * - Por defecto es una simulación: lista lo que borraría y no modifica nada.
 * - Con `--apply` borra, en una transacción, solo los borradores que cumplen TODAS las condiciones de
 *   una firma de `test-data.mjs` (patrón de título, cuerpo literal y dueño esperado con rol ISSUER).
 *   Si el número de filas borradas no coincide con el previsto, revierte.
 * - No toca usuarios, sesiones, borradores del seed ni la auditoría (append-only por diseño).
 * - Se niega a ejecutarse contra una base que no esté en localhost.
 *
 * Uso: node tests/security/cleanup-test-drafts.mjs [--apply]
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BROWSER_DRAFT, G1_DRAFT } from './test-data.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const apply = process.argv.includes('--apply');
const env = Object.fromEntries(
  readFileSync(join(root, '.env'), 'utf8')
    .split(/\r?\n/)
    .filter((l) => /^[A-Z0-9_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);

const url = new URL(env.DATABASE_URL);
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
  u.role = 'ISSUER' AND (
    (d.title ~ $1 AND d.body = $2 AND u.email ~ $3)
    OR (d.title ~ $4 AND d.body = $5 AND u.email = $6)
  )`;
const params = [
  G1_DRAFT.titlePattern.source,
  G1_DRAFT.body,
  G1_DRAFT.ownerPattern.source,
  BROWSER_DRAFT.titlePattern.source,
  BROWSER_DRAFT.body,
  seedIssuer,
];

function sourceOf(row) {
  if (G1_DRAFT.titlePattern.test(row.title) && row.body === G1_DRAFT.body && G1_DRAFT.ownerPattern.test(row.email)) {
    return G1_DRAFT.source;
  }
  if (BROWSER_DRAFT.titlePattern.test(row.title) && row.body === BROWSER_DRAFT.body && row.email === seedIssuer) {
    return BROWSER_DRAFT.source;
  }
  return null;
}

const client = new Client({ connectionString: env.DATABASE_URL });
await client.connect();
try {
  await client.query('BEGIN');
  const total = (await client.query('SELECT count(*)::int AS n FROM "Draft"')).rows[0].n;
  const { rows } = await client.query(
    `SELECT d.id, d.title, d.body, u.email, d."createdAt"
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
    console.log(`  - ${row.id}  "${row.title}"  (${row.email}, ${row.createdAt.toISOString()})  ← ${sourceOf(row)}`);
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
