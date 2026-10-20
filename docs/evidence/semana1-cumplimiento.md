# Reporte de cumplimiento — Semana 1 (GATE G1)

Fecha de ejecución: 2026-10-19 · Entorno: Windows 11, Node 24.14.0, pnpm 12.14.0, Docker Desktop 29.4, PostgreSQL 17-alpine.
Elaborado por ATLAS a partir de ejecuciones reales; cada resultado enlaza su evidencia.

## Resultado del GATE G1

| Prueba | Resultado obligatorio | Evidencia automatizada | Aceptación de caja negra (ATLAS) | Estado |
| --- | --- | --- | --- | --- |
| P01 | Login seguro, sesiones y roles | e2e `P01: autenticación y ciclo de la sesión` | [`g1/P01.json`](g1/P01.json), 18/18 pasos | **APROBADO** |
| P02a | Anónimo publica → 401 | e2e `P02a: un anónimo no puede publicar (401)` | [`g1/P02a.json`](g1/P02a.json), 4/4 pasos | **APROBADO** |
| P02b | Autenticado sin permisos → 403 | e2e `P02b: usuarios autenticados sin derecho no publican` | [`g1/P02b.json`](g1/P02b.json), 10/10 pasos | **APROBADO** |
| P09 | Solicitudes excesivas → 429 | e2e `P09: rate limiting (429 con Retry-After)` | [`g1/P09.json`](g1/P09.json), 6/6 pasos | **APROBADO** |
| P13 | Firma Node verificada con Web Crypto; alterado rechazado | Vitest `P13 …`, 46/46 ([`g1/P13-vitest.json`](g1/P13-vitest.json)) | Comprobación independiente ([log](g1/logs/09-p13-atlas-independiente.log)) | **APROBADO** |

Cada prueba se verificó dos veces y por vías independientes: una con la suite del agente responsable (Jest o Vitest) y otra
con el script de caja negra de ATLAS (`tests/security/g1-acceptance.mjs`), que ataca la API compilada (`node dist/main`) por HTTP
y con PostgreSQL real, sin compartir código con la implementación.

---

### P01 — Login seguro, sesiones y roles

- **Preparación:** API compilada en `:3000`, BD migrada y seed aplicado (ADMIN y AUDITOR con contraseñas del `.env` local, que no se versiona). Durante la prueba el ADMIN provisiona dos emisores con contraseñas aleatorias.
- **Pasos:** `GET /auth/csrf` → login con contraseña errónea y con cuenta inexistente → login correcto → inspección de la cookie → `/auth/me` → provisión de emisores, incluido un intento de *mass assignment* con `role` → login del AUDITOR y del emisor → logout → reutilización de la cookie anterior → token inventado.
- **Esperado:** 401 genérico e idéntico para contraseña errónea y cuenta inexistente; cookie `HttpOnly; SameSite=Strict; Path=/`; roles y permisos según la matriz; ningún `passwordHash` en las respuestas; el AUDITOR no provisiona; tras el logout la cookie anterior devuelve 401.
- **Observado:** todo lo esperado. Cookie real: `as_session=<43 caracteres>; Max-Age=28800; Path=/; HttpOnly; SameSite=Strict`. Campo extra `role` → 400 `VALIDATION_FAILED`. La e2e comprueba además que el hash empieza por `$argon2id$`, la caducidad por inactividad y la caducidad absoluta.
- **Evidencia:** [`g1/P01.json`](g1/P01.json), [`logs/07-g1-acceptance.log`](g1/logs/07-g1-acceptance.log), [`logs/05-test-e2e.log`](g1/logs/05-test-e2e.log).

### P02a — Anónimo intenta publicar → 401

- **Preparación:** el emisor A crea un borrador real (201).
- **Pasos:** `POST /drafts/:id/publish` sin cookie ni token CSRF; repetición con un token CSRF anónimo válido; `GET /drafts/:id` anónimo.
- **Esperado / observado:** 401 `UNAUTHENTICATED` en los tres casos. La autenticación se evalúa antes que el CSRF, así que un anónimo nunca recibe otro código.
- **Evidencia:** [`g1/P02a.json`](g1/P02a.json).

### P02b — Autenticado sin permisos → 403

- **Preparación:** borrador del emisor A; sesiones del AUDITOR, del ADMIN, del emisor B y del emisor A.
- **Pasos y resultado observado:**

  | Caso | Esperado | Observado |
  | --- | --- | --- |
  | AUDITOR publica (sin `alerts:publish`) | 403 FORBIDDEN | 403 FORBIDDEN |
  | ADMIN publica (separación de funciones) | 403 FORBIDDEN | 403 FORBIDDEN |
  | Emisor B publica / lee el borrador de A (propiedad) | 403 FORBIDDEN | 403 FORBIDDEN |
  | Emisor A sin `X-CSRF-Token` | 403 CSRF_INVALID | 403 CSRF_INVALID |
  | Emisor A con el token CSRF de otra sesión | 403 CSRF_INVALID | 403 CSRF_INVALID |
  | Emisor A con `Origin: https://atacante.example` | 403 CSRF_INVALID | 403 CSRF_INVALID |
  | Control positivo: emisor A, propietario | 501 PUBLICATION_NOT_IMPLEMENTED | 501 PUBLICATION_NOT_IMPLEMENTED |
  | Auditoría | PUBLICATION_DENIED y PUBLICATION_AUTHORIZED | ambas presentes |

- El 501 es intencionado: la autorización se concede y se audita, pero la firma real llega con el firmante aislado de la semana 2. No se simula.
- **Evidencia:** [`g1/P02b.json`](g1/P02b.json).

### P09 — Solicitudes excesivas → 429

- **Preparación:** límites del `.env`: login por cuenta 5 fallos cada 15 min, login por IP 10 cada 60 s, usuario autenticado 120 cada 60 s. Antes de empezar se espera 61 s para que la ventana de login por IP esté vacía.
- **Pasos y resultado observado:**
  1. 6 intentos fallidos contra una misma cuenta: `401,401,401,401,401,429`, con `Retry-After: 895`.
  2. Intentos con cuentas rotadas desde la misma IP: el primer 429 llega en el intento 11, exactamente al superar 10.
  3. 121 peticiones autenticadas del emisor A: 120 respuestas 200 y la 121.ª 429.
  4. El emisor B, desde la misma IP, sigue recibiendo 200: el límite es por usuario.
  5. La auditoría registra `RATE_LIMITED`.
- **Evidencia:** [`g1/P09.json`](g1/P09.json).

### P13 — Interoperabilidad ECDSA Node.js ⇄ Web Crypto

- **Preparación:** `tests/fixtures/crypto/p13-vectors.json` se generó con `pnpm --filter @alertasegura/verification vectors` usando una clave P-256 efímera que se descarta. El archivo solo contiene la JWK pública y las firmas.
- **Pasos:**
  - 5 vectores verificados con `crypto.subtle`: forma canónica JCS, SHA-256 y firma P1363 de 64 bytes;
  - firma con `node:crypto` y verificación con Web Crypto, y también al revés;
  - comprobación del `kid` = SHA-256 de la SPKI.
- **Rechazos comprobados:**
  - campo cambiado o con el último decimal alterado;
  - clave añadida o eliminada, cambio de tipo;
  - cada uno de los 512 bits de la firma invertido;
  - firma de otro documento, otra clave pública, firma DER y longitudes erróneas;
  - JWK con `d`.
- **Comprobación independiente de ATLAS:** documento nuevo con Unicode, emoji y `1e21`, firmado con `node:crypto` y verificado con el paquete compilado. Si se reordenan las claves sigue verificando, porque JCS produce la misma forma canónica. Si se altera un valor se rechaza.
- **Observado:** 46/46 pruebas P13 en verde, más 66 pruebas adicionales de JCS (RFC 8785 §3.2.2, §3.2.3 y Apéndice B) y de base64url.
- **En Google Chrome 155 real:** el laboratorio `/laboratorio/criptografia` verifica los 5 vectores firmados en Node con el `crypto.subtle` nativo del navegador (5 de 5) y rechaza el campo alterado, la clave añadida y el bit de firma invertido; al restaurar el original vuelve a verificar.
- **Evidencia:** [`g1/P13-vitest.json`](g1/P13-vitest.json), [`logs/08-p13.log`](g1/logs/08-p13.log), [`logs/09-p13-atlas-independiente.log`](g1/logs/09-p13-atlas-independiente.log), capturas [`navegador/06`–`09`](g1/navegador/) y [`navegador/resultado.json`](g1/navegador/resultado.json).

### Recorrido en navegador real (Chrome 155)

`tests/security/browser-walkthrough.mjs` controla el Chrome instalado (headless, `playwright-core`) contra la PWA de Vite y la API real.
17 de 17 comprobaciones aprobadas ([`navegador/resultado.json`](g1/navegador/resultado.json), [log](g1/logs/13-navegador-chrome.log)):

| Comprobación | Observado | Captura |
| --- | --- | --- |
| `/panel` sin sesión redirige a `/login` | redirección | [02](g1/navegador/02-panel-sin-sesion-redirige.png) |
| Contraseña errónea | «Correo o contraseña incorrectos.» y contraseña borrada | [03](g1/navegador/03-login-error-generico.png) |
| Login del emisor 1 | panel con rol ISSUER y sus permisos | [04](g1/navegador/04-panel-emisor.png) |
| Cookie en el navegador | `as_session` HttpOnly, SameSite=Strict, Path=/ | — |
| Lo que ve JavaScript | `document.cookie` vacío; localStorage y sessionStorage vacíos | — |
| Crear borrador desde la UI | `POST /drafts` 201 con `X-CSRF-Token` y aparece en la lista | [05](g1/navegador/05-borrador-creado.png) |
| P13 en el navegador | 5/5 válidos; alteraciones rechazadas | [06](g1/navegador/06-lab-vectores-validos.png)–[09](g1/navegador/09-lab-bit-firma.png) |
| Vista móvil 360 px | sin desbordamiento horizontal en laboratorio y panel | [10](g1/navegador/10-lab-movil-360.png), [11](g1/navegador/11-panel-movil-360.png) |
| Logout | cookie eliminada y `/panel` vuelve a pedir login | [12](g1/navegador/12-logout.png) |
| Consola | sin errores inesperados (solo los 401 que provoca la propia prueba) | — |

La primera ejecución detectó un defecto real: el laboratorio se desbordaba 8 px a 360 px de ancho (rejilla `.kv` con `1fr` y el `kid` sin cortes). CIPHER lo corrigió y la segunda ejecución quedó en verde.

---

## Condiciones de finalización

| Condición | Estado | Evidencia |
| --- | --- | --- |
| El monorepo funciona | ✅ | `pnpm build` y `pnpm typecheck` con exit 0 ([02](g1/logs/02-build.log), [03](g1/logs/03-typecheck.log)) |
| PostgreSQL en Docker | ✅ | `infra-postgres-1` healthy ([01](g1/logs/01-db.log)) |
| Prisma aplica sus migraciones | ✅ | 2 migraciones aplicadas; `migrate deploy` sin pendientes; la e2e las aplica en una base nueva en cada ejecución |
| NestJS inicia y conecta con la BD | ✅ | `GET /health` → `{"status":"ok","database":"up"}` ([06](g1/logs/06-api-server.log)) |
| React inicia y consume la API | ✅ | Integración por el proxy de Vite ([`integracion-web-api.json`](g1/integracion-web-api.json)) y recorrido en Chrome real ([`navegador/`](g1/navegador/)) |
| Login | ✅ | P01 |
| Sesiones seguras | ✅ | P01: HttpOnly, SameSite=Strict, rotación, revocación, caducidades, solo el hash en BD |
| Roles y permisos | ✅ | P01, P02b |
| Control de propiedad | ✅ | P02b (emisor B → 403) |
| Protección CSRF | ✅ | P02b: sin token, token ajeno y Origin ajeno → 403; pruebas unitarias del servicio CSRF |
| Rate limiting | ✅ | P09 |
| Auditoría básica | ✅ | P02b, P09 y e2e `admin-audit` (incluido el trigger append-only) |
| Canonicalización JCS | ✅ | Vectores RFC 8785 en Vitest |
| Firmas Node/Web Crypto compatibles | ✅ | P13 |
| P01, P02a, P02b, P09 y P13 aprobadas | ✅ | Tabla superior |
| Documentación de arquitectura, riesgos y modelo SQL | ✅ | [arquitectura](../architecture/README.md), [amenazas T1–T11](../threat-model/README.md), [base de datos](../database/README.md) |
| Evidencias de las pruebas | ✅ | `docs/evidence/g1/` |
| Compilación y pruebas obligatorias en verde | ✅ | Unitarias 209/209 (api 62, web 35, verification 112), e2e 77/77 y lint sin errores en api y web ([04](g1/logs/04-test.log), [05](g1/logs/05-test-e2e.log), [12](g1/logs/12-lint-api.log)) |
| README con ejecución local | ✅ | [`README.md`](../../README.md) |

## Pruebas negativas de seguridad adicionales (ATLAS)

| Comprobación | Resultado |
| --- | --- |
| Claves privadas (PEM o JWK con `d`) en los 218 archivos versionables | Ninguna |
| `.env`, cliente Prisma generado o `dist/` en Git | No (todos ignorados) |
| Valores reales de `CSRF_SECRET`, contraseñas del seed o de PostgreSQL en archivos versionables | Ninguno |
| Material privado en el bundle de la PWA | Ninguno (solo aparece el texto del error `PRIVATE_KEY_REJECTED`) |
| Revisión de código de sesiones, CSRF, autenticación, propiedad y auditoría | Sin defectos de seguridad; ver hallazgos menores |

## Hallazgos de la revisión y correcciones

| Hallazgo | Responsable | Estado |
| --- | --- | --- |
| Script de aceptación sobrescribía la cabecera CSRF explícita (falso fallo en P02b) | ATLAS | Corregido |
| `shared` no exportaba los tipos `DraftResponse` y `DraftListResponse` | ATLAS | Corregido |
| Aclaraciones del contrato: límite por cuenta solo cuenta fallos, auditoría de 429 deduplicada, nuevo CSRF tras una sesión rechazada | ATLAS | Documentado en `api-contract.md` |
| `apps/api`: 351 errores de ESLint (338 de formato prettier, 13 de reglas) y script `lint` con `--fix` | FORGE | Corregido sin desactivar reglas; `lint` solo verifica |
| `CSRF_SECRET` aceptaba el placeholder de `.env.example` | FORGE | Corregido y cubierto en `env.spec.ts` |
| 3 pruebas de `apps/web` fallaban por timeout con `pnpm test` en paralelo | CIPHER | Corregido (timeouts y `user-event` sin retardo); 2 ejecuciones seguidas en verde |
| Script de integración fallaba con 429 si se ejecutaba justo después de P09 | ATLAS | Corregido: respeta `Retry-After` y lo registra |
| Laboratorio criptográfico desbordaba 8 px a 360 px (detectado en Chrome real) | CIPHER | Corregido en `styles.css` (`minmax(0, 1fr)` y `overflow-wrap: anywhere`) |

Tras las correcciones se repitieron build, lint, typecheck, unitarias, e2e, aceptación G1 e integración contra la API reconstruida: todo en verde.

## Riesgos pendientes

Ver [modelo de amenazas](../threat-model/README.md#riesgos-pendientes): firmante aislado (semana 2), HTTPS y `COOKIE_SECURE`
en despliegue, rate limiting en memoria de un solo proceso, ausencia de MFA y rotación de claves. Además:

- El límite por cuenta permite a un atacante bloquear temporalmente una cuenta conocida (DoS dirigido). Mitigación futura: límite por cuenta+IP o CAPTCHA.
- Sin purga periódica de sesiones caducadas.
- La API usa el rol propietario de PostgreSQL; queda pendiente un rol de aplicación con privilegios mínimos.
- No hay cabecera CSP en el frontend de desarrollo; debe fijarla el servidor que sirva la PWA en producción.

## Cómo reproducir

```bash
pnpm db:up && pnpm db:deploy && pnpm db:seed
pnpm build && pnpm typecheck && pnpm test && pnpm test:e2e
pnpm --filter @alertasegura/api start:prod &      # API compilada en :3000
node tests/security/g1-acceptance.mjs             # P01, P02a, P02b, P09 → docs/evidence/g1/*.json
pnpm --filter @alertasegura/verification exec vitest run -t P13
pnpm dev:web &                                    # PWA en :5173
node tests/security/integration-web-proxy.mjs     # integración PWA ⇄ API por el proxy
node tests/security/browser-walkthrough.mjs       # recorrido en Chrome real → docs/evidence/g1/navegador/
```
