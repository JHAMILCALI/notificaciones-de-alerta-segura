/**
 * Firmas de los borradores que crean las pruebas automatizadas. Los scripts de prueba generan sus
 * borradores con estas constantes y `cleanup-test-drafts.mjs` solo borra lo que coincide con ellas.
 * Cambiar un formato aquí cambia a la vez la creación y la limpieza.
 * Desde la semana 2 (D-4) el texto vive en `mensaje`; solo se limpian borradores sin publicar.
 */

/** g1-acceptance.mjs: borrador del emisor A (dado de alta en la prueba con correo @example.test). */
export const G1_DRAFT = {
  source: 'tests/security/g1-acceptance.mjs',
  mensaje: (suffix) => `Alerta G1 ${suffix}: contenido ficticio de prueba.`,
  mensajePattern: /^Alerta G1 [0-9a-f]{8}: contenido ficticio de prueba\.$/,
  ownerPattern: /^emisor-[ab]-[0-9a-f]{8}@example\.test$/,
};

/** g2-acceptance.mjs: borradores de los emisores A y B de la aceptación G2. */
export const G2_DRAFT = {
  source: 'tests/security/g2-acceptance.mjs',
  mensaje: (suffix) => `Alerta G2 ${suffix}: simulacro de laboratorio, no es una alerta real.`,
  mensajePattern: /^Alerta G2 [0-9a-f]{8}: simulacro de laboratorio, no es una alerta real\.$/,
  ownerPattern: /^g2-emisor-[ab]-[0-9a-f]{8}@example\.test$/,
};

/** browser-walkthrough.mjs: borrador creado desde la UI por el emisor 1 del seed. */
export const BROWSER_DRAFT = {
  source: 'tests/security/browser-walkthrough.mjs',
  mensaje: (time) => `Prueba en navegador ${time}: borrador creado desde Chrome real.`,
  mensajePattern: /^Prueba en navegador \d{2}:\d{2}:\d{2}: borrador creado desde Chrome real\.$/,
  /** El dueño se compara con SEED_ISSUER1_EMAIL del .env. */
  ownerEnv: 'SEED_ISSUER1_EMAIL',
};
