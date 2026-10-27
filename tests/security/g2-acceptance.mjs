#!/usr/bin/env node
/**
 * Aceptación GATE G2 de caja negra (ATLAS), independiente de las pruebas de SHIRO y MOTO:
 *   P02c  emisor B cancela una alerta del emisor A → 403 y CANCEL_DENIED
 *   P03   alterar mensaje, fecha o severidad de una alerta servida por la API → la firma no verifica;
 *         los bytes guardados en PostgreSQL son exactamente los firmados
 *   P06   cancelación válida → CANCELADA verificable; eventos falsificados rechazados; historial visible
 *   P07   UPDATE / DELETE / TRUNCATE con el rol alertasegura_app → permission denied (42501)
 *   P15   la API no puede leer la clave del firmante (infra/scripts/p15-api-isolation.sh)
 *   P16   firma de EVENTO usada como ALERTA (y otras mezclas de tipo) sobre documentos REALES → rechazo
 *
 * Requisitos: perfil Docker `g2` en marcha (postgres + signer + api), manifiesto emitido con la CLI y montado
 * en la API, raíz de laboratorio en ~/.alertasegura-lab/root. Credenciales del seed en `.env`.
 * Uso: node tests/security/g2-acceptance.mjs [--base http://localhost:3000/api/v1] [--api-container infra-api-1]
 */
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  Client,
  Evidence,
  assertHealthy,
  boliviaDraft,
  env,
  provisionIssuer,
  requireEnv,
  root,
  strongPassword,
  uniq,
} from './lib/harness.mjs';
import { G2_DRAFT } from './test-data.mjs';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(name);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const BASE = arg('--base', env.G2_API_BASE ?? 'http://localhost:3000/api/v1');
const API_CONTAINER = arg('--api-container', env.G2_API_CONTAINER ?? 'infra-api-1');
const PG_CONTAINER = arg('--pg-container', env.G2_PG_CONTAINER ?? 'infra-postgres-1');
const ROOT_JWK_FILE = arg('--root-jwk', join(homedir(), '.alertasegura-lab', 'root', 'root.public.jwk.json'));
const evidenceDir = join(root, 'docs', 'evidence', 'g2');

const V = await import(pathToFileURL(join(root, 'packages', 'verification', 'dist', 'index.js')).href);

const client = (name) => new Client(name, BASE);
const evidence = (id, title, prep) => new Evidence(id, title, prep, BASE);

/** Ejecuta `fn` esperando un VerificationError; devuelve su código o 'ACEPTADO' si no lanzó. */
async function rejectionCode(fn) {
  try {
    await fn();
    return 'ACEPTADO';
  } catch (error) {
    return error?.code ?? String(error);
  }
}

const decode = (envelope) => JSON.parse(Buffer.from(envelope.payload_canonico, 'base64url').toString('utf8'));

/** Sobre con el payload modificado y re-canonicalizado; conserva la firma original. */
function tamper(envelope, mutate, { recomputeHash = true } = {}) {
  const payload = decode(envelope);
  mutate(payload);
  const bytes = Buffer.from(V.canonicalize(payload), 'utf8');
  return {
    ...envelope,
    payload_canonico: bytes.toString('base64url'),
    hash_payload: recomputeHash ? createHash('sha256').update(bytes).digest('hex') : envelope.hash_payload,
  };
}

/** psql dentro del contenedor de PostgreSQL. La contraseña viaja por variable de entorno, no por argumento. */
function psql(user, password, sql) {
  const r = spawnSync(
    'docker',
    ['exec', '-e', `PGPASSWORD=${password}`, PG_CONTAINER, 'psql', '-h', '127.0.0.1', '-U', user, '-d', env.POSTGRES_DB ?? 'alertasegura', '-v', 'ON_ERROR_STOP=1', '-tAc', sql],
    { encoding: 'utf8' },
  );
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}`.trim() };
}

async function publishNew(issuerClient, overrides = {}) {
  let r = await issuerClient.request('POST', '/drafts', { body: boliviaDraft(G2_DRAFT.mensaje(uniq()), overrides) });
  if (r.status !== 201) return { r };
  r = await issuerClient.request('POST', `/drafts/${r.json.draft.id}/publish`);
  return { r, alerta: r.json?.alerta };
}

async function main() {
  mkdirSync(evidenceDir, { recursive: true });
  await assertHealthy(BASE);
  const results = [];

  // ---------- Preparación común: emisores, sesiones y confianza ----------
  const issuerA = { email: `g2-emisor-a-${uniq()}@example.test`, password: strongPassword() };
  const issuerB = { email: `g2-emisor-b-${uniq()}@example.test`, password: strongPassword() };
  for (const [label, u] of [['A', issuerA], ['B', issuerB]]) {
    const out = provisionIssuer({ email: u.email, name: `Emisor ${label} G2`, password: u.password });
    if (!out.ok) throw new Error(`No se pudo dar de alta al emisor ${label}: ${out.output}`);
    u.id = out.id;
  }
  const a = client('emisorA');
  const b = client('emisorB');
  const auditor = client('auditor');
  const admin = client('admin');
  for (const [c, email, pw] of [
    [a, issuerA.email, issuerA.password],
    [b, issuerB.email, issuerB.password],
    [auditor, requireEnv('SEED_AUDITOR_EMAIL'), requireEnv('SEED_AUDITOR_PASSWORD')],
    [admin, requireEnv('SEED_ADMIN_EMAIL'), requireEnv('SEED_ADMIN_PASSWORD')],
  ]) {
    const r = await c.login(email, pw);
    if (r.status !== 200) throw new Error(`Login de ${c.name} falló (${r.status})`);
  }

  // Confianza: el manifiesto que sirve la API se verifica con la raíz anclada (fuera del repo).
  const rootJwk = JSON.parse(readFileSync(ROOT_JWK_FILE, 'utf8'));
  const manifestRes = await client('anonimo').request('GET', '/trust/manifest');
  const manifest = await V.verifyManifest({ envelope: manifestRes.json?.manifiesto, rootJwk, ahora: new Date(), versionMinima: 1 });
  const signerJwk = manifest.claves.find((c) => c.key_id === manifest.key_id_activo).jwk;
  console.log(`Manifiesto v${manifest.version} verificado con la raíz; clave activa ${manifest.key_id_activo}`);
  const trust = { manifestVersion: manifest.version, keyIdActivo: manifest.key_id_activo, rootKeyId: manifest.root_key_id };

  // ---------- P02c ----------
  const p02c = evidence('P02c', 'Emisor A cancela alerta de emisor B → 403 por propiedad', {
    ...trust,
    actors: ['emisor A (dueño)', 'emisor B (ajeno)', 'ADMIN', 'anónimo'],
  });
  const pubA = await publishNew(a);
  p02c.check('Preparación: emisor A publica una alerta', '201', String(pubA.r.status), pubA.r.status === 201, { alertaId: pubA.alerta?.id });
  const alertaA = pubA.alerta;
  let r = await b.request('POST', `/alerts/${alertaA.id}/cancel`, { body: {} });
  p02c.expectStatus('Emisor B cancela la alerta de A', r, 403, 'FORBIDDEN');
  r = await admin.request('POST', `/alerts/${alertaA.id}/cancel`, { body: {} });
  p02c.expectStatus('ADMIN cancela (no tiene alerts:cancel)', r, 403, 'FORBIDDEN');
  r = await client('anonimo2').request('POST', `/alerts/${alertaA.id}/cancel`, { body: {} });
  p02c.expectStatus('Anónimo cancela', r, 401, 'UNAUTHENTICATED');
  r = await auditor.request('GET', '/audit?limit=100');
  const denied = (r.json?.entries ?? []).filter((e) => e.action === 'CANCEL_DENIED' && e.actorId === issuerB.id);
  p02c.check('Auditoría registra CANCEL_DENIED del emisor B', 'presente', denied.length ? `presente (${denied.length})` : 'ausente', denied.length > 0);
  r = await client('lector').request('GET', `/alerts/${alertaA.id}`);
  const estadoTrasIntento = await V.verifyDocument({ envelope: r.json?.alerta?.estado, jwk: signerJwk, tipoEsperado: 'ESTADO' });
  p02c.check('La alerta sigue VIGENTE y sin eventos (estado firmado verificado)', 'VIGENTE, 0 eventos', `${estadoTrasIntento.estado}, ${r.json?.alerta?.eventos?.length} eventos`, estadoTrasIntento.estado === 'VIGENTE' && r.json.alerta.eventos.length === 0);
  results.push(p02c);

  // ---------- P03 (API) ----------
  const p03 = evidence('P03', 'Alterar mensaje, fecha o severidad del JSON → firma no válida', {
    ...trust,
    alertaId: alertaA.id,
    note: 'Se modifica el documento servido por la API, se re-canonicaliza y se conserva la firma original.',
  });
  const servida = (await client('lector').request('GET', `/alerts/${alertaA.id}`)).json.alerta;
  const doc = await V.verifyDocument({ envelope: servida.alerta, jwk: signerJwk, tipoEsperado: 'ALERTA' });
  p03.check('Control: la alerta original verifica con la clave del manifiesto', 'válida', `válida (${doc.tipo}, ${doc.zona.departamento}, ${doc.severidad})`, doc.alerta_id === alertaA.id);
  const mutations = [
    ['mensaje alterado', (p) => { p.mensaje = p.mensaje.replace('simulacro', 'EVACUACIÓN INMEDIATA'); }],
    ['expira_en adelantada 3 días', (p) => { p.expira_en = new Date(Date.parse(p.expira_en) + 3 * 86400e3).toISOString().replace(/\.\d{3}Z$/, 'Z'); }],
    ['severidad NARANJA → ROJA', (p) => { p.severidad = 'ROJA'; }],
    ['departamento cambiado', (p) => { p.zona.departamento = 'SANTA_CRUZ'; }],
  ];
  for (const [label, mutate] of mutations) {
    const code = await rejectionCode(() => V.verifyDocument({ envelope: tamper(servida.alerta, mutate), jwk: signerJwk, tipoEsperado: 'ALERTA' }));
    p03.check(`${label} (hash recalculado)`, 'SIGNATURE_INVALID', code, code === 'SIGNATURE_INVALID');
  }
  const codeHash = await rejectionCode(() => V.verifyDocument({ envelope: tamper(servida.alerta, mutations[0][1], { recomputeHash: false }), jwk: signerJwk, tipoEsperado: 'ALERTA' }));
  p03.check('mensaje alterado conservando hash_payload', 'HASH_MISMATCH', codeHash, codeHash === 'HASH_MISMATCH');
  p03.check(
    'La copia `resumen` no interviene: el mensaje verificado sale de los bytes firmados',
    'mensaje verificado = resumen.mensaje',
    doc.mensaje === servida.resumen.mensaje ? 'coinciden' : 'difieren',
    doc.mensaje === servida.resumen.mensaje,
  );
  const ownerPw = env.DATABASE_MIGRATION_URL ? decodeURIComponent(new URL(env.DATABASE_MIGRATION_URL).password) : requireEnv('POSTGRES_PASSWORD');
  const db = psql(
    env.POSTGRES_USER ?? 'alertasegura',
    ownerPw,
    `SELECT encode("payloadCanonico",'base64') || '|' || "hashPayload" || '|' || encode(sha256("payloadCanonico"),'hex') FROM "AlertaPublicada" WHERE id = '${alertaA.id}'`,
  );
  const [b64, hashCol, hashCalc] = db.out.replace(/\s+/g, '').split('|');
  const bytesIguales = Buffer.from(b64 ?? '', 'base64').equals(Buffer.from(servida.alerta.payload_canonico, 'base64url'));
  p03.check('PostgreSQL guarda exactamente los bytes firmados (bytea) y su SHA-256', 'bytes iguales y hash coherente', `bytes ${bytesIguales ? 'iguales' : 'distintos'}; hash columna=calculado: ${hashCol === hashCalc}`, db.status === 0 && bytesIguales && hashCol === hashCalc && hashCol === servida.alerta.hash_payload);
  results.push(p03);

  // ---------- P06 (backend) ----------
  const p06 = evidence('P06', 'Cancelación válida / evento falsificado + historial', { ...trust, alertaId: alertaA.id });
  r = await a.request('POST', `/alerts/${alertaA.id}/cancel`, { body: {} });
  p06.expectStatus('El dueño cancela su alerta', r, 201);
  const cancelada = r.json?.alerta;
  const { evento } = await V.verifyCancelacion(cancelada.alerta, cancelada.eventos[0], signerJwk);
  p06.check('El EVENTO verifica y su hash_alerta es el SHA-256 de los bytes de la alerta', 'válido', `válido (hash_alerta=${evento.hash_alerta.slice(0, 12)}…)`, evento.hash_alerta === cancelada.alerta.hash_payload);
  const estado = await V.verifyDocument({ envelope: cancelada.estado, jwk: signerJwk, tipoEsperado: 'ESTADO' });
  const frescura = (Date.parse(estado.expires_at) - Date.parse(estado.issued_at)) / 1000;
  p06.check('ESTADO firmado: CANCELADA, secuencia 1, encadena el hash del evento, frescura ≤ 600 s', 'CANCELADA/1/hash/≤600', `${estado.estado}/${estado.secuencia}/${estado.ultimo_evento_hash === cancelada.eventos[0].hash_payload ? 'hash' : 'otro'}/${frescura}`, estado.estado === 'CANCELADA' && estado.secuencia === 1 && estado.ultimo_evento_hash === cancelada.eventos[0].hash_payload && frescura <= 600);
  r = await a.request('POST', `/alerts/${alertaA.id}/cancel`, { body: {} });
  p06.expectStatus('Cancelar dos veces', r, 409, 'CONFLICT');
  r = await client('lector2').request('GET', `/alerts/${alertaA.id}`);
  p06.check('Historial visible en la consulta pública', '1 evento', `${r.json?.alerta?.eventos?.length} evento(s)`, r.status === 200 && r.json.alerta.eventos.length === 1);

  // Falsificaciones.
  const otra = await publishNew(a, { tipo: 'HELADA', severidad: 'AMARILLA', zona: { departamento: 'ORURO', municipio: null } });
  const cancelOtra = await a.request('POST', `/alerts/${otra.alerta.id}/cancel`, { body: {} });
  const eventoOtra = cancelOtra.json?.alerta?.eventos?.[0];
  let code = await rejectionCode(() => V.verifyCancelacion(cancelada.alerta, eventoOtra, signerJwk));
  p06.check('Evento legítimo de OTRA alerta presentado para esta', 'CANCELACION_ALERTA_MISMATCH', code, code === 'CANCELACION_ALERTA_MISMATCH');
  code = await rejectionCode(() => V.verifyCancelacion(cancelada.alerta, tamper(cancelada.eventos[0], (p) => { p.hash_alerta = '0'.repeat(64); }), signerJwk));
  p06.check('Evento con hash_alerta alterado', 'SIGNATURE_INVALID', code, code === 'SIGNATURE_INVALID');
  const rogue = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rogueJwk = (({ kty, crv, x, y }) => ({ kty, crv, x, y }))(rogue.publicKey.export({ format: 'jwk' }));
  const rogueKid = await V.computeKid(rogueJwk);
  const forgedPayload = { ...evento, evento_id: randomUUID(), key_id: rogueKid };
  const forgedBytes = Buffer.from(V.canonicalize(forgedPayload), 'utf8');
  const forged = {
    payload_canonico: forgedBytes.toString('base64url'),
    hash_payload: createHash('sha256').update(forgedBytes).digest('hex'),
    firma: sign('sha256', forgedBytes, { key: rogue.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'),
    key_id: rogueKid,
  };
  code = await rejectionCode(() => V.verifyCancelacion(servida.alerta, forged, signerJwk));
  p06.check('Evento bien formado firmado con una clave ajena al manifiesto', 'KEY_ID_MISMATCH', code, code === 'KEY_ID_MISMATCH');
  code = await rejectionCode(() => V.verifyCancelacion(servida.alerta, { ...forged, key_id: manifest.key_id_activo }, signerJwk));
  p06.check('El mismo evento ajeno haciéndose pasar por la clave activa', 'rechazo', code, code !== 'ACEPTADO');
  results.push(p06);

  // ---------- P16 (documentos reales) ----------
  const p16 = evidence('P16', 'Sustituir firma EVENTO por firma ALERTA → rechazo por tipo_doc o bytes', { ...trust, alertaId: alertaA.id });
  const realAlerta = cancelada.alerta;
  const realEvento = cancelada.eventos[0];
  const realEstado = cancelada.estado;
  const cases = [
    ['EVENTO real presentado como ALERTA', () => V.verifyDocument({ envelope: realEvento, jwk: signerJwk, tipoEsperado: 'ALERTA' }), 'TIPO_DOC_MISMATCH'],
    ['ALERTA real presentada como EVENTO', () => V.verifyDocument({ envelope: realAlerta, jwk: signerJwk, tipoEsperado: 'EVENTO' }), 'TIPO_DOC_MISMATCH'],
    ['ESTADO real presentado como EVENTO', () => V.verifyDocument({ envelope: realEstado, jwk: signerJwk, tipoEsperado: 'EVENTO' }), 'TIPO_DOC_MISMATCH'],
    ['Bytes de la ALERTA con la firma del EVENTO', () => V.verifyDocument({ envelope: { ...realAlerta, firma: realEvento.firma }, jwk: signerJwk, tipoEsperado: 'ALERTA' }), 'SIGNATURE_INVALID'],
    ['Bytes del EVENTO con la firma de la ALERTA', () => V.verifyDocument({ envelope: { ...realEvento, firma: realAlerta.firma }, jwk: signerJwk, tipoEsperado: 'EVENTO' }), 'SIGNATURE_INVALID'],
    ['tipo_doc del EVENTO reescrito a ALERTA (firma original)', () => V.verifyDocument({ envelope: tamper(realEvento, (p) => { p.tipo_doc = 'ALERTA'; }), jwk: signerJwk, tipoEsperado: 'ALERTA' }), 'SIGNATURE_INVALID'],
  ];
  for (const [label, fn, expected] of cases) {
    const c = await rejectionCode(fn);
    p16.check(label, expected, c, c === expected);
  }
  results.push(p16);

  // ---------- P07 ----------
  const p07 = evidence('P07', 'UPDATE/DELETE SQL sobre publicaciones con el rol app → privilegio denegado', {
    role: 'alertasegura_app (contraseña APP_DB_PASSWORD del .env, no registrada)',
    alertaId: alertaA.id,
  });
  const appPw = requireEnv('APP_DB_PASSWORD');
  const appUser = 'alertasegura_app';
  const control = psql(appUser, appPw, `SELECT count(*) FROM "AlertaPublicada" WHERE id = '${alertaA.id}'`);
  p07.check('Control: el rol app sí puede leer la alerta', 'SELECT → 1', `${control.status === 0 ? 'SELECT → ' + control.out : control.out}`, control.status === 0 && control.out === '1');
  const statements = [];
  for (const table of ['AlertaPublicada', 'EventoAlerta', 'EstadoAlerta', 'AuditLog', 'ClavePublica']) {
    const where = table === 'AuditLog' || table === 'ClavePublica' ? 'true' : table === 'AlertaPublicada' ? `id = '${alertaA.id}'` : `"alertaId" = '${alertaA.id}'`;
    const setCol = { AlertaPublicada: '"mensaje" = \'alterado\'', EventoAlerta: '"firma" = \'x\'', EstadoAlerta: '"firma" = \'x\'', AuditLog: '"action" = \'X\'', ClavePublica: '"jwk" = \'{}\'' }[table];
    statements.push([`UPDATE "${table}" SET ${setCol} WHERE ${where}`]);
    statements.push([`DELETE FROM "${table}" WHERE ${where}`]);
    statements.push([`TRUNCATE "${table}"`]);
  }
  for (const [sql] of statements) {
    const res = psql(appUser, appPw, sql);
    const deniedSql = res.status !== 0 && /permission denied/i.test(res.out);
    p07.check(sql, 'permission denied', res.out.split('\n')[0] || `exit ${res.status}`, deniedSql);
  }
  for (const method of ['PUT', 'PATCH', 'DELETE']) {
    const res = await a.request(method, `/alerts/${alertaA.id}`, { body: method === 'DELETE' ? undefined : { mensaje: 'x' } });
    p07.check(`La API no expone ${method} /alerts/:id`, '404', String(res.status), res.status === 404);
  }
  const after = psql(env.POSTGRES_USER ?? 'alertasegura', ownerPw, `SELECT "hashPayload" FROM "AlertaPublicada" WHERE id = '${alertaA.id}'`);
  p07.check('La alerta conserva su hash original tras los intentos', servida.alerta.hash_payload.slice(0, 16) + '…', after.out.slice(0, 16) + '…', after.out === servida.alerta.hash_payload);
  results.push(p07);

  // ---------- P15 ----------
  const p15 = evidence('P15', 'Usuario del proceso API intenta leer la clave de firma → permiso denegado', {
    script: 'infra/scripts/p15-api-isolation.sh (SHIRO), ejecutado por ATLAS contra el contenedor en marcha',
    container: API_CONTAINER,
  });
  const p15run = spawnSync('bash', ['infra/scripts/p15-api-isolation.sh', API_CONTAINER], { cwd: root, encoding: 'utf8' });
  const lines = `${p15run.stdout ?? ''}${p15run.stderr ?? ''}`.split(/\r?\n/).filter((l) => /^(PASS|FAIL)/.test(l));
  for (const line of lines) p15.check(line.replace(/^(PASS|FAIL)\s+/, ''), 'PASS', line.slice(0, 4), line.startsWith('PASS'));
  p15.check('El script termina sin fallos', 'exit 0', `exit ${p15run.status}`, p15run.status === 0 && lines.length > 0);
  writeFileSync(join(evidenceDir, 'P15-salida.txt'), `${p15run.stdout ?? ''}${p15run.stderr ?? ''}`);
  results.push(p15);

  for (const ev of results) writeFileSync(join(evidenceDir, `${ev.id}.json`), JSON.stringify(ev, null, 2) + '\n');
  console.log('\nResumen G2:');
  for (const ev of results) console.log(`  ${ev.id}: ${ev.approved ? 'APROBADO' : 'NO APROBADO'} (${ev.steps.filter((s) => s.result === 'OK').length}/${ev.steps.length})`);
  process.exitCode = results.every((e) => e.approved) ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 2;
});

