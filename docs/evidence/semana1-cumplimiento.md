# Reporte de cumplimiento — Semana 1 (GATE G1)

Validación final: 2026-10-20 (UTC) · Entorno: Windows 11, Node 24.14.0, pnpm 12.14.0, Docker Desktop 29.4,
PostgreSQL 17-alpine, Google Chrome 155 · Referencia oficial: `AlertaSegura_Propuesta_Definitiva_Seguridad_4_Semanas.pdf`
(sección 11: «G1 · P01, P02a–b, P09, P13; roles y bytes compatibles»).
Elaborado por ATLAS a partir de ejecuciones reales; cada resultado enlaza su evidencia.

## Resultado del GATE G1

Las pruebas G1 se aprueban con el **backend**: suites e2e de Jest contra PostgreSQL real (API construida en el proceso
de prueba) y la aceptación de caja negra de ATLAS contra la API compilada (`node dist/main`) por HTTP. P13 se aprueba
con Vitest. El recorrido en Chrome es **evidencia complementaria** y no sustituye a ninguna de ellas.

| Prueba | Resultado obligatorio (sección 10) | e2e backend (Jest, PostgreSQL real) | Caja negra (ATLAS) | Estado |
| --- | --- | --- | --- | --- |
| P01 | Login correcto, roles; sesión protegida y alta de emisores auditada | `P01: autenticación y ciclo de la sesión` 23/23 + `Provisión de emisores (solo ADMIN)` 8/8 | [`P01.json`](g1/P01.json) 19/19 | **APROBADO** |
| P02a | Petición anónima intenta publicar → 401 | `P02a: un anónimo no puede publicar (401)` 6/6 | [`P02a.json`](g1/P02a.json) 4/4 | **APROBADO** |
| P02b | Autenticado sin rol intenta publicar → 403 | `P02b: usuarios autenticados sin derecho no publican` 10/10 | [`P02b.json`](g1/P02b.json) 10/10 | **APROBADO** |
| P09 | Exceder login con mismo usuario / distintos usuarios desde una IP → 429 | `P09: rate limiting (429 con Retry-After)` 15/15 | [`P09.json`](g1/P09.json) 6/6 | **APROBADO** |
| P13 | Firma Node vs. Web Crypto con vector válido y alterado | Vitest `P13 …` 46/46 ([`P13-vitest.json`](g1/P13-vitest.json)) | Comprobación independiente ([log](g1/logs/09-p13-atlas-independiente.log)) | **APROBADO** |

Totales de la validación final: e2e 77/77 ([`e2e-jest.json`](g1/e2e-jest.json), [log](g1/logs/05-test-e2e.log)),
caja negra 39/39 ([log](g1/logs/07-g1-acceptance.log)), P13 46/46 ([log](g1/logs/08-p13.log)).

---

### P01 — Login seguro, sesiones y roles

- **Preparación:** API compilada en `:3000`, BD migrada y seed aplicado (ADMIN y AUDITOR con contraseñas del `.env` local, que no se versiona). El ADMIN provisiona dos emisores `@example.test` con contraseñas aleatorias.
- **Pasos:** `GET /auth/csrf` → login con contraseña errónea y con cuenta inexistente → login correcto → inspección de la cookie → `/auth/me` → alta de emisores, incluido un intento de *mass assignment* con `role` → login del AUDITOR y del emisor → consulta de auditoría → logout → reutilización de la cookie anterior → token inventado.
- **Esperado:** 401 genérico e idéntico para contraseña errónea y cuenta inexistente; cookie `HttpOnly; SameSite=Strict; Path=/`; roles y permisos según la matriz; ningún `passwordHash` en las respuestas; alta de emisores registrada en auditoría; tras el logout la cookie anterior devuelve 401.
- **Observado:** todo lo esperado. Cookie real: `as_session=<43 caracteres>; Max-Age=28800; Path=/; HttpOnly; SameSite=Strict`. Campo extra `role` → 400 `VALIDATION_FAILED`. `ISSUER_PROVISIONED` registrado para los dos emisores. La e2e comprueba además que el hash empieza por `$argon2id$`, la caducidad por inactividad y absoluta, la rotación de sesión y `Secure` + `__Host-` con `COOKIE_SECURE=true`.
- **Evidencia:** [`P01.json`](g1/P01.json), [`e2e-jest.json`](g1/e2e-jest.json).

### P02a — Anónimo intenta publicar → 401

- **Preparación:** el emisor A crea un borrador real (201).
- **Pasos:** `POST /drafts/:id/publish` sin cookie ni token CSRF; repetición con un token CSRF anónimo válido; `GET /drafts/:id` anónimo.
- **Esperado / observado:** 401 `UNAUTHENTICATED` en los tres casos; sin publicación; denegación auditada. La autenticación se evalúa antes que el CSRF, así que un anónimo nunca recibe otro código.
- **Evidencia:** [`P02a.json`](g1/P02a.json).

### P02b — Autenticado sin rol intenta publicar → 403

- **Preparación:** borrador del emisor A; sesiones del AUDITOR, del ADMIN, del emisor B y del emisor A.

  | Caso | Esperado | Observado |
  | --- | --- | --- |
  | AUDITOR publica (sin `alerts:publish`) | 403 FORBIDDEN | 403 FORBIDDEN |
  | ADMIN publica (la propuesta prohíbe que publique) | 403 FORBIDDEN | 403 FORBIDDEN |
  | Emisor B publica / lee el borrador de A (propiedad; anticipa P02c) | 403 FORBIDDEN | 403 FORBIDDEN |
  | Emisor A sin `X-CSRF-Token` | 403 CSRF_INVALID | 403 CSRF_INVALID |
  | Emisor A con el token CSRF de otra sesión | 403 CSRF_INVALID | 403 CSRF_INVALID |
  | Emisor A con `Origin: https://atacante.example` | 403 CSRF_INVALID | 403 CSRF_INVALID |
  | Control positivo: emisor A, propietario | 501 PUBLICATION_NOT_IMPLEMENTED | 501 PUBLICATION_NOT_IMPLEMENTED |
  | Auditoría | PUBLICATION_DENIED y PUBLICATION_AUTHORIZED | ambas presentes |

- El 501 es intencionado: la autorización se concede y se audita, pero la publicación firmada es de la semana 2 (D6–D7). No se simula.
- **Evidencia:** [`P02b.json`](g1/P02b.json).

### P09 — Solicitudes excesivas → 429

- **Preparación:** límites del `.env`: login por cuenta 5 fallos / 15 min, login por IP 10 / 60 s, usuario autenticado 120 / 60 s. Se espera 61 s para empezar con la ventana de login por IP vacía.
- **Pasos y resultado observado:**
  1. Mismo usuario: 6 intentos fallidos → `401,401,401,401,401,429`, con `Retry-After`.
  2. Distintos usuarios desde la misma IP: el primer 429 llega en el intento 11, al superar 10.
  3. 121 peticiones autenticadas del emisor A: 120 respuestas 200 y la 121.ª 429.
  4. El emisor B, desde la misma IP, sigue recibiendo 200: el límite es por usuario.
  5. La auditoría registra `RATE_LIMITED`.
- **Evidencia:** [`P09.json`](g1/P09.json).

### P13 — Interoperabilidad ECDSA Node.js ⇄ Web Crypto

- **Preparación:** `tests/fixtures/crypto/p13-vectors.json`, generado con `pnpm --filter @alertasegura/verification vectors` y una clave P-256 efímera descartada. Solo contiene la JWK pública y las firmas.
- **Pasos:** 5 vectores verificados con `crypto.subtle` (forma canónica JCS, SHA-256 y firma P1363 de 64 bytes); firma con `node:crypto` → verificación Web Crypto y al revés; `kid` = SHA-256 de la SPKI.
- **Rechazos comprobados:** campo cambiado o último decimal alterado; clave añadida o eliminada; cambio de tipo; cada uno de los 512 bits de la firma invertido; firma de otro documento; otra clave pública; firma DER; longitudes erróneas; JWK con `d`.
- **Comprobación independiente de ATLAS:** documento nuevo (Unicode, emoji, `1e21`) firmado con `node:crypto` y verificado con el paquete compilado; reordenar claves sigue verificando (misma forma canónica) y alterar un valor se rechaza.
- **Observado:** 46/46 P13, más 66 pruebas de JCS (RFC 8785 §3.2.2, §3.2.3 y Apéndice B) y base64url. «Bytes y formatos equivalentes»: el SHA-256 de la forma canónica coincide en Node y en Web Crypto.
- **Evidencia:** [`P13-vitest.json`](g1/P13-vitest.json), [`logs/08-p13.log`](g1/logs/08-p13.log), [`logs/09-p13-atlas-independiente.log`](g1/logs/09-p13-atlas-independiente.log).

---

## Evidencia complementaria: recorrido en Chrome real

`tests/security/browser-walkthrough.mjs` (`pnpm test:browser`) controla el Google Chrome 155 instalado (headless, `playwright-core`)
contra la PWA de Vite y la API real. 17/17 comprobaciones ([`navegador/resultado.json`](g1/navegador/resultado.json),
[log](g1/logs/13-navegador-chrome.log)). Las 12 capturas vigentes:

| # | Captura | Qué demuestra |
| --- | --- | --- |
| 01 | [`01-inicio.png`](g1/navegador/01-inicio.png) | Inicio público (consulta ciudadana) |
| 02 | [`02-panel-sin-sesion-redirige.png`](g1/navegador/02-panel-sin-sesion-redirige.png) | Ruta protegida sin sesión redirige a `/login` |
| 03 | [`03-login-error-generico.png`](g1/navegador/03-login-error-generico.png) | Contraseña errónea: mensaje genérico y contraseña borrada |
| 04 | [`04-panel-emisor.png`](g1/navegador/04-panel-emisor.png) | Login del emisor 1: rol ISSUER y permisos |
| 05 | [`05-borrador-creado.png`](g1/navegador/05-borrador-creado.png) | Borrador creado desde la UI (`POST /drafts` 201 con `X-CSRF-Token`) |
| 06 | [`06-lab-vectores-validos.png`](g1/navegador/06-lab-vectores-validos.png) | P13 en el navegador: 5/5 vectores Node verificados con Web Crypto nativo |
| 07 | [`07-lab-campo-alterado.png`](g1/navegador/07-lab-campo-alterado.png) | Campo alterado → «Firma INVÁLIDA» |
| 08 | [`08-lab-clave-anadida.png`](g1/navegador/08-lab-clave-anadida.png) | Clave añadida → «Firma INVÁLIDA» |
| 09 | [`09-lab-bit-firma.png`](g1/navegador/09-lab-bit-firma.png) | Bit de la firma invertido → «Firma INVÁLIDA» |
| 10 | [`10-lab-movil-360.png`](g1/navegador/10-lab-movil-360.png) | Laboratorio a 360 px sin desbordamiento |
| 11 | [`11-panel-movil-360.png`](g1/navegador/11-panel-movil-360.png) | Panel a 360 px sin desbordamiento |
| 12 | [`12-logout.png`](g1/navegador/12-logout.png) | Logout: cookie eliminada y `/panel` vuelve a pedir login |

Además, sin captura: cookie `as_session` HttpOnly/SameSite=Strict vista desde el navegador; `document.cookie`,
`localStorage` y `sessionStorage` vacíos; sin errores inesperados en consola. La primera ejecución detectó un desbordamiento
de 8 px a 360 px (corregido por CIPHER). Integración por el proxy de Vite: [`integracion-web-api.json`](g1/integracion-web-api.json).

## Matriz de amenazas T1–T11

La matriz de [`docs/threat-model`](../threat-model/README.md) se corrigió para reproducir la sección 09 de la propuesta
oficial. La versión anterior usaba once amenazas definidas por ATLAS que **no coincidían** con las oficiales; se sustituyeron
sin conservar las antiguas. Estado tras la semana 1:

| Estado | Amenazas |
| --- | --- |
| Mitigado (prueba oficial aprobada en G1) | T1 (P01, P02a–b), T8 (P09; cuotas de publicación en S2) |
| Parcial (control parcial probado; prueba oficial en un gate posterior) | T2 (P13 listo; P03/P07/P11), T7 (trigger append-only; HMAC P08 en S3), T10 (propiedad sobre borradores; P02c en G2) |
| Pendiente (gates G2–G4) | T3, T4, T5, T6, T9, T11 |

OE1 (100 % de amenazas altas con control y prueba asignados al cierre de S1): las siete amenazas ALTAS (T1, T2, T3, T5,
T6, T10, T11) tienen control y prueba asignados en la matriz.

## Datos de prueba: limpieza específica

`tests/security/cleanup-test-drafts.mjs` (`pnpm test:cleanup`, simulación; `pnpm test:cleanup -- --apply` para borrar):

- Solo selecciona borradores que cumplen a la vez el patrón de título, el cuerpo literal y el dueño esperado definidos en
  [`tests/security/test-data.mjs`](../../tests/security/test-data.mjs), módulo que también usan los scripts que los crean.
- Simulación por defecto; con `--apply` borra por id en una transacción, vuelve a comprobar las condiciones en el `DELETE`
  y revierte si el número de filas no coincide. Se niega a actuar fuera de `localhost`.
- No toca usuarios, sesiones, la auditoría (append-only) ni los borradores del seed.
- Ejecución: 8 borradores de prueba eliminados en total (7 + 1 de la validación final); se conservan los 2 «Simulacro» del seed
  ([log 1](g1/logs/14-limpieza-borradores.log), [log final](g1/logs/14-limpieza-borradores-final.log)).
- Las e2e no dejan datos: crean y eliminan su propia base. Los JSON de evidencia citan ids de borradores ya eliminados.

## Condiciones de finalización

| Condición | Estado | Evidencia |
| --- | --- | --- |
| El monorepo funciona | ✅ | `pnpm build` y `pnpm typecheck` con exit 0 ([02](g1/logs/02-build.log), [03](g1/logs/03-typecheck.log)) |
| PostgreSQL en Docker | ✅ | `infra-postgres-1` healthy ([01](g1/logs/01-db.log)) |
| Prisma aplica sus migraciones | ✅ | 2 migraciones; la e2e las aplica en una base nueva en cada ejecución |
| NestJS inicia y conecta con la BD | ✅ | `GET /health` → `{"status":"ok","database":"up"}` ([06](g1/logs/06-api-server.log)) |
| React inicia y consume la API | ✅ | Proxy de Vite ([`integracion-web-api.json`](g1/integracion-web-api.json)) y Chrome real ([`navegador/`](g1/navegador/)) |
| Login, sesiones seguras, roles y permisos | ✅ | P01, P02b |
| Control de propiedad | ✅ | P02b (emisor B → 403) |
| Protección CSRF (Origin + token) | ✅ | P02b; pruebas unitarias del servicio CSRF |
| Rate limiting por IP y usuario | ✅ | P09 |
| Auditoría básica | ✅ | P01 (alta auditada), P02b, P09, e2e `Auditoría: consulta y append-only` |
| Canonicalización JCS y firmas Node/Web Crypto | ✅ | P13 |
| P01, P02a, P02b, P09 y P13 aprobadas | ✅ | Tabla superior |
| Arquitectura, riesgos y modelo SQL | ✅ | [arquitectura](../architecture/README.md), [amenazas T1–T11](../threat-model/README.md), [base de datos](../database/README.md) |
| Evidencias de las pruebas | ✅ | `docs/evidence/g1/` |
| Compilación y pruebas obligatorias en verde | ✅ | Unitarias 209/209, e2e 77/77, lint sin errores ([04](g1/logs/04-test.log), [05](g1/logs/05-test-e2e.log), [12](g1/logs/12-lint-api.log)) |
| README con ejecución local | ✅ | [`README.md`](../../README.md) |

## Pruebas negativas de seguridad adicionales (ATLAS)

| Comprobación | Resultado |
| --- | --- |
| Claves privadas (PEM o JWK con `d`) en archivos versionables | Ninguna |
| `.env`, cliente Prisma generado o `dist/` en Git | No (ignorados) |
| Valores reales de `CSRF_SECRET` o contraseñas en archivos versionables y evidencias | Ninguno |
| Material privado en el bundle de la PWA | Ninguno (solo el texto del error `PRIVATE_KEY_REJECTED`) |
| Revisión de código de sesiones, CSRF, autenticación, propiedad y auditoría | Sin defectos de seguridad |

## Hallazgos de la revisión y correcciones

| Hallazgo | Responsable | Estado |
| --- | --- | --- |
| Matriz T1–T11 no coincidía con la sección 09 de la propuesta oficial | ATLAS | Corregida |
| La caja negra no comprobaba que la alta de emisores quede auditada (P01) | ATLAS | Añadido y aprobado |
| Script de aceptación sobrescribía la cabecera CSRF explícita (falso fallo en P02b) | ATLAS | Corregido |
| `shared` no exportaba `DraftResponse` y `DraftListResponse` | ATLAS | Corregido |
| `apps/api`: 351 errores de ESLint y `lint` con `--fix` | FORGE | Corregido sin desactivar reglas |
| `CSRF_SECRET` aceptaba el placeholder de `.env.example` | FORGE | Corregido y probado |
| 3 pruebas de `apps/web` inestables por timeout en paralelo | CIPHER | Corregido; 2 ejecuciones seguidas en verde |
| Script de integración fallaba con 429 justo después de P09 | ATLAS | Respeta `Retry-After` |
| Laboratorio desbordaba 8 px a 360 px (Chrome real) | CIPHER | Corregido |
| Borradores residuales de las pruebas en la BD de desarrollo | ATLAS | Limpieza específica implementada y aplicada |

## Diferencias con la propuesta oficial (pendientes de decisión)

Al contrastar la implementación con la propuesta completa (no solo la sección 09) aparecen estas diferencias. No se han
cambiado porque afectan al diseño o al contrato y requieren decisión del autor:

| # | Propuesta oficial | Implementado en S1 | Impacto |
| --- | --- | --- | --- |
| D-1 | §03: altas de emisores **mediante script del responsable de laboratorio**; el administrador gestiona usuarios ordinarios | `POST /admin/issuers` (ADMIN, auditado) | Contradice §03; afecta a P01 y T1 |
| D-2 | §03 y §02: actores administrador, emisores A/B y ciudadano | Rol adicional **AUDITOR** (solo lectura de auditoría) | Rol no previsto; P02b también lo usa |
| D-3 | §02 y §06: una base React con rutas **`/admin` y `/alertas`** | `/panel`, `/` (consulta) y `/laboratorio/criptografia` | Nombres de ruta distintos |
| D-4 | §08: BORRADOR con `tipo`, `zona`, `severidad`, `mensaje`, `datos_temporales` | `title`, `body`, `severity` | Los campos firmados en S2 (`tipo`, `zona`, `emitida_en`, `expira_en`) no existen aún en el borrador |
| D-5 | §05 RNF01: **TLS de laboratorio** (asociado a P01) | HTTP local; `Secure`/`__Host-` probados solo por configuración | Cookie `Secure` no ejercitada sobre TLS real |
| D-6 | Portada y §06: API **Express** | **NestJS** sobre `@nestjs/platform-express` | Exigido por las instrucciones del proyecto; Express sigue siendo el servidor HTTP |

## Pendiente

- **Decisiones D-1 a D-5** (D-6 queda documentada como desviación justificada).
- Semana 2 (G2): firmante aislado, publicación atómica, `ALERTA_PUBLICADA`, rol SQL sin UPDATE/DELETE, cancelación, P02c, P03, P06, P07, P15, P16.
- Riesgos de implementación: rate limiting en memoria de un solo proceso; bloqueo temporal de cuentas conocidas por el límite por cuenta; API con el rol propietario de PostgreSQL; sin purga de sesiones caducadas; sin CSP en el servidor de desarrollo.
- Los usuarios emisores `@example.test` que crea la aceptación permanecen en la BD de desarrollo (la limpieza se limitó a borradores, como se pidió).

## Cómo reproducir

```bash
pnpm db:up && pnpm db:deploy && pnpm db:seed
pnpm build && pnpm typecheck && pnpm lint && pnpm test && pnpm test:e2e
pnpm --filter @alertasegura/api start:prod &      # API compilada en :3000
pnpm test:g1                                      # P01, P02a, P02b, P09 (caja negra) → docs/evidence/g1/*.json
pnpm --filter @alertasegura/verification exec vitest run -t P13
pnpm dev:web &                                    # PWA en :5173
node tests/security/integration-web-proxy.mjs     # integración PWA ⇄ API por el proxy
pnpm test:browser                                 # complementaria: Chrome real → docs/evidence/g1/navegador/
pnpm test:cleanup                                 # simulación; añadir -- --apply para borrar los borradores de prueba
```
