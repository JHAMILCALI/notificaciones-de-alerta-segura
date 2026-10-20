/**
 * Firmas de los borradores que crean las pruebas automatizadas. Los scripts de prueba generan sus
 * borradores con estas constantes y `cleanup-test-drafts.mjs` solo borra lo que coincide con ellas.
 * Cambiar un formato aquí cambia a la vez la creación y la limpieza.
 */

/** g1-acceptance.mjs: borrador del emisor A (provisionado en la prueba con correo @example.test). */
export const G1_DRAFT = {
  source: 'tests/security/g1-acceptance.mjs',
  title: (suffix) => `Alerta G1 ${suffix}`,
  titlePattern: /^Alerta G1 [0-9a-f]{8}$/,
  body: 'Contenido ficticio de prueba para G1.',
  ownerPattern: /^emisor-[ab]-[0-9a-f]{8}@example\.test$/,
};

/** browser-walkthrough.mjs: borrador creado desde la UI por el emisor 1 del seed. */
export const BROWSER_DRAFT = {
  source: 'tests/security/browser-walkthrough.mjs',
  title: (time) => `Prueba en navegador ${time}`,
  titlePattern: /^Prueba en navegador \d{2}:\d{2}:\d{2}$/,
  body: 'Borrador creado desde Chrome real para la evidencia de la semana 1.',
  /** El dueño se compara con SEED_ISSUER1_EMAIL del .env. */
  ownerEnv: 'SEED_ISSUER1_EMAIL',
};
