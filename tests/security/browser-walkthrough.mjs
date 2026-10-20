#!/usr/bin/env node
/**
 * Recorrido de la PWA en Google Chrome real (headless) contra la API real: P01 y P13 en el navegador,
 * cookies HttpOnly, CSRF desde la UI, laboratorio criptográfico con Web Crypto nativo y vista móvil.
 * Requiere Chrome instalado, `pnpm dev:web` y la API en marcha. Credenciales: emisor 1 del seed (.env).
 * Salida: docs/evidence/g1/navegador/ (capturas PNG + resultado.json).
 * Uso: node tests/security/browser-walkthrough.mjs
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const env = Object.fromEntries(
  readFileSync(join(root, '.env'), 'utf8')
    .split(/\r?\n/)
    .filter((l) => /^[A-Z0-9_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
);
const WEB = 'http://localhost:5173';
const out = join(root, 'docs', 'evidence', 'g1', 'navegador');
mkdirSync(out, { recursive: true });

const steps = [];
const consoleErrors = [];
let shot = 0;
function check(step, ok, observed, screenshot) {
  steps.push({ step, result: ok ? 'OK' : 'FALLO', observed, ...(screenshot ? { screenshot } : {}) });
  console.log(`  ${ok ? '✔' : '✘'} ${step} — ${observed}`);
}
async function capture(page, name) {
  const file = `${String(++shot).padStart(2, '0')}-${name}.png`;
  await page.screenshot({ path: join(out, file), fullPage: true });
  return file;
}

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const version = browser.version();
const context = await browser.newContext({ viewport: { width: 1280, height: 860 }, locale: 'es-BO' });
const page = await context.newPage();
page.on('console', (m) => m.type() === 'error' && consoleErrors.push(m.text()));
page.on('pageerror', (e) => consoleErrors.push(String(e)));

try {
  // 1. Inicio público
  await page.goto(WEB + '/');
  await page.waitForLoadState('networkidle');
  check('Inicio público (consulta ciudadana) carga', (await page.title()).length > 0, await page.locator('h1').first().innerText(), await capture(page, 'inicio'));

  // 2. Ruta protegida sin sesión
  await page.goto(WEB + '/panel');
  await page.waitForURL('**/login**', { timeout: 10000 });
  check('/panel sin sesión redirige a /login', page.url().includes('/login'), page.url(), await capture(page, 'panel-sin-sesion-redirige'));

  // 3. Contraseña errónea
  await page.fill('#login-email', env.SEED_ISSUER1_EMAIL);
  await page.fill('#login-password', 'contraseña-incorrecta-123');
  await page.click('button[type=submit]');
  const alert = page.locator('form [role=alert]');
  await alert.filter({ hasText: /./ }).waitFor({ timeout: 10000 });
  const alertText = await alert.innerText();
  check('Contraseña errónea: mensaje genérico (401)', alertText.length > 0 && !/no existe/i.test(alertText), alertText, await capture(page, 'login-error-generico'));
  check('El campo contraseña se limpia tras el error', (await page.inputValue('#login-password')) === '', 'vacío');

  // 4. Login correcto
  await page.fill('#login-email', env.SEED_ISSUER1_EMAIL);
  await page.fill('#login-password', env.SEED_ISSUER1_PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL('**/panel', { timeout: 15000 });
  await page.locator('#panel-title').waitFor();
  const panelText = await page.locator('main').innerText();
  check('Login emisor 1 → /panel con rol y permisos', /ISSUER|Emisor/i.test(panelText) && /alerts:publish/.test(panelText), panelText.split('\n').slice(0, 8).join(' | '), await capture(page, 'panel-emisor'));

  const cookies = await context.cookies(WEB);
  const session = cookies.find((c) => c.name === 'as_session');
  check('Cookie as_session HttpOnly + SameSite=Strict en el navegador', !!session && session.httpOnly && session.sameSite === 'Strict', session ? `httpOnly=${session.httpOnly} sameSite=${session.sameSite} path=${session.path}` : 'ausente');
  const jsView = await page.evaluate(() => ({ cookie: document.cookie, ls: localStorage.length, ss: sessionStorage.length }));
  check('JavaScript no ve la sesión ni el CSRF; nada en local/sessionStorage', !/as_session|as_csrf/.test(jsView.cookie) && jsView.ls === 0 && jsView.ss === 0, `document.cookie="${jsView.cookie}" localStorage=${jsView.ls} sessionStorage=${jsView.ss}`);

  // 5. Crear un borrador (POST con CSRF desde el navegador)
  await page.goto(WEB + '/panel/borradores');
  await page.locator('#new-draft-title').waitFor();
  const title = `Prueba en navegador ${new Date().toISOString().slice(11, 19)}`;
  await page.fill('#draft-title', title);
  await page.fill('#draft-body', 'Borrador creado desde Chrome real para la evidencia de la semana 1.');
  await page.selectOption('#draft-severity', 'WARNING');
  const [resp] = await Promise.all([
    page.waitForResponse((r) => r.url().endsWith('/api/v1/drafts') && r.request().method() === 'POST'),
    page.click('form button[type=submit]'),
  ]);
  const sentCsrf = resp.request().headers()['x-csrf-token'];
  await page.locator('.draft-list h3', { hasText: title }).waitFor({ timeout: 10000 });
  check('Crear borrador desde la UI: 201 con X-CSRF-Token y aparece en la lista', resp.status() === 201 && !!sentCsrf, `POST /drafts ${resp.status()}, X-CSRF-Token ${sentCsrf ? 'enviado' : 'ausente'}`, await capture(page, 'borrador-creado'));

  // 6. Laboratorio criptográfico (P13 en el navegador)
  await page.goto(WEB + '/laboratorio/criptografia');
  const summary = page.getByTestId('baseline-summary');
  await summary.filter({ hasText: /verificados/ }).waitFor({ timeout: 15000 });
  const summaryText = await summary.innerText();
  const subtle = await page.evaluate(() => typeof crypto?.subtle?.verify === 'function' && window.isSecureContext);
  check('P13 en Chrome: los vectores firmados en Node verifican con Web Crypto', /^(\d+) de \1 /.test(summaryText) && subtle, `${summaryText}; crypto.subtle nativo=${subtle}`, await capture(page, 'lab-vectores-validos'));

  const result = page.getByTestId('lab-result');
  const readResult = async () => (await result.innerText()).trim();
  const baselineResult = await readResult();
  await page.getByRole('button', { name: 'Alterar un campo' }).click();
  await page.waitForTimeout(400);
  const tampered = await readResult();
  check('Campo alterado → firma rechazada', tampered !== baselineResult, `antes: "${baselineResult}" · después: "${tampered}"`, await capture(page, 'lab-campo-alterado'));

  await page.getByRole('button', { name: 'Restaurar original' }).click();
  await page.waitForTimeout(400);
  await page.getByRole('button', { name: 'Añadir una clave' }).click();
  await page.waitForTimeout(400);
  const added = await readResult();
  check('Clave añadida → firma rechazada', added === tampered, `"${added}"`, await capture(page, 'lab-clave-anadida'));

  await page.getByRole('button', { name: 'Restaurar original' }).click();
  await page.waitForTimeout(400);
  await page.getByRole('button', { name: 'Alterar un bit de la firma' }).click();
  await page.waitForTimeout(400);
  const flipped = await readResult();
  check('Bit de la firma alterado → rechazada', flipped === tampered, `"${flipped}"`, await capture(page, 'lab-bit-firma'));

  await page.getByRole('button', { name: 'Restaurar original' }).click();
  await page.waitForTimeout(400);
  const restored = await readResult();
  check('Restaurar original → vuelve a verificar', restored === baselineResult, `"${restored}"`);

  // 7. Vista móvil (360 px)
  await page.setViewportSize({ width: 360, height: 780 });
  await page.waitForTimeout(300);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check('Laboratorio a 360 px sin desbordamiento horizontal', overflow <= 0, `scrollWidth - clientWidth = ${overflow}px`, await capture(page, 'lab-movil-360'));
  await page.goto(WEB + '/panel');
  await page.locator('#panel-title').waitFor();
  const overflowPanel = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check('Panel a 360 px sin desbordamiento horizontal', overflowPanel <= 0, `${overflowPanel}px`, await capture(page, 'panel-movil-360'));
  await page.setViewportSize({ width: 1280, height: 860 });

  // 8. Logout
  await page.getByRole('button', { name: /cerrar sesión|salir/i }).click();
  await page.waitForURL((u) => !u.pathname.startsWith('/panel'), { timeout: 10000 });
  await page.goto(WEB + '/panel');
  await page.waitForURL('**/login**', { timeout: 10000 });
  const after = (await context.cookies(WEB)).some((c) => c.name === 'as_session');
  check('Logout: cookie eliminada y /panel vuelve a pedir login', !after && page.url().includes('/login'), `as_session presente=${after}; url=${page.url()}`, await capture(page, 'logout'));
} catch (error) {
  check('Recorrido completo sin excepciones', false, String(error).slice(0, 300), await capture(page, 'error').catch(() => undefined));
} finally {
  // Errores de consola esperados: los 401/429 que la propia prueba provoca.
  const unexpected = consoleErrors.filter((e) => !/status of 40[13]|status of 429/.test(e));
  check('Sin errores inesperados en la consola', unexpected.length === 0, unexpected.length ? unexpected.slice(0, 3).join(' || ') : `${consoleErrors.length} errores esperados (401 del login erróneo / sesión)`);
  const ok = steps.every((s) => s.result === 'OK');
  writeFileSync(
    join(out, 'resultado.json'),
    JSON.stringify({ at: new Date().toISOString(), browser: `Google Chrome ${version} (headless)`, web: WEB, steps, status: ok ? 'APROBADO' : 'NO APROBADO' }, null, 2) + '\n',
  );
  console.log(`\nChrome ${version}: ${ok ? 'APROBADO' : 'NO APROBADO'}`);
  await browser.close();
  process.exitCode = ok ? 0 : 1;
}
