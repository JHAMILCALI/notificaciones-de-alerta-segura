# Informe FORGE — Semana 1 (backend, base de datos, seguridad del servidor)

Estado: `typecheck`, `build`, `test` y `test:e2e` de `apps/api` en verde. Sin commits.

## 1. Resultado de las pruebas (salida real)

Ejecutadas en `apps/api` (cada script reconstruye antes `@alertasegura/database`).

```
$ pnpm run typecheck        -> exit 0   (tsc --noEmit, strict)
$ pnpm run build            -> exit 0   (nest build)
$ pnpm run test             -> exit 0
  Test Suites: 7 passed, 7 total
  Tests:       61 passed, 61 total
$ pnpm run test:e2e         -> exit 0   (PostgreSQL 17 real, jest --runInBand)
  Test Suites: 4 passed, 4 total
  Tests:       77 passed, 77 total
$ pnpm --filter @alertasegura/database typecheck -> exit 0
```

Unitarias (61): Argon2id (prefijo `$argon2id$`, parámetros m=19456/t=2/p=1, sal distinta, hash señuelo, hash mal formado, tiempos comparables); CSRF (válido, ausente, alterado, cabecera≠cookie, de otra sesión, anónimo vs. sesión, otro secreto); matriz RBAC completa (3 roles × 6 permisos contra `ROLE_PERMISSIONS`, `PUBLICATION_DENIED`, ruta sin política = denegada); guard de propiedad (propietario, otro emisor, 404, sin usuario); ventana deslizante; validación de config; saneado de auditoría y «la auditoría no tumba la petición».

E2E (77), contra una base `alertasegura_test_<aleatorio>` creada por `globalSetup` en el mismo servidor, con `prisma migrate deploy` real y borrada en `globalTeardown`:

| Archivo | `describe` | Qué demuestra |
| --- | --- | --- |
| `test/p01-auth.e2e-spec.ts` | `P01: autenticación y ciclo de la sesión` | login 200 + `LoginResponse`; cookie `HttpOnly; SameSite=Strict; Path=/` (sin `Secure` en HTTP, con `__Host-` + `Secure` si `COOKIE_SECURE=true`); `/auth/me` con rol y permisos de los 3 roles; 401 genérico idéntico (contraseña errónea / correo inexistente / cuenta DISABLED); hash `$argon2id$`; en BD solo SHA-256 del token; logout revoca (cookie reenviada a mano → 401); rotación de sesión y fijación de sesión; caducidad absoluta e inactividad → 401 y `AUTH_SESSION_REJECTED`; cuenta desactivada invalida la sesión; login sin CSRF u Origin ajeno → 403 |
| `test/p02-authorization.e2e-spec.ts` | `P02a: un anónimo no puede publicar (401)` | 401 con y sin token CSRF (anónimo, inventado), con id inexistente o inválido; todas las rutas protegidas → 401; `ACCESS_DENIED` auditado sin actor |
| | `P02b: usuarios autenticados sin derecho no publican` | AUDITOR → 403, ADMIN → 403, ISSUER no propietario → 403 (todos `PUBLICATION_DENIED`), propietario → 501 `PUBLICATION_NOT_IMPLEMENTED` + `PUBLICATION_AUTHORIZED`, sin CSRF → 403 `CSRF_INVALID` (antes que el RBAC), CSRF alterado / de otra sesión / anónimo / Origin ajeno → 403, 404 borrador inexistente, 400 antes que 403 |
| `test/p09-rate-limit.e2e-spec.ts` | `P09: rate limiting (429 con Retry-After)` | login por cuenta (límite inyectado 3: 4.º → 429 con `Retry-After`, `RATE_LIMITED` auditado), login por IP (3), usuario autenticado (5), global, `TRUST_PROXY` off/on, cuenta inexistente, normalización de correo, dedup de auditoría |
| `test/admin-audit.e2e-spec.ts` | `Provisión de emisores (solo ADMIN)`, `Borradores y autorización por propiedad`, `Auditoría: consulta y append-only`, `Robustez HTTP: errores, cabeceras y salud` | provisión solo ADMIN (201, 409, 403, 401, CSRF), campo extra `role` → 400, entradas inválidas → 400 sin repetir valores, propiedad de borradores, auditoría legible por ADMIN/AUDITOR, **UPDATE/DELETE/TRUNCATE en `AuditLog` fallan por trigger**, sin secretos en auditoría, caída de auditoría no tumba la petición, 500 sin trazas ni mensajes de Prisma, JSON malformado 400, cuerpo > 100 kb 413, cabeceras helmet, sin CORS, `/health` 200 y 503 |

## 2. Prueba de caja negra de ATLAS (`tests/security/g1-acceptance.mjs`)

Ejecutada contra `node dist/main` real con el seed: P01, P02a y P09 aprobados. **P02b: 1 fallo, y es un defecto del script, no de la API.**
En `Client.request` (línea ~51) se hace `h = { ...headers }` y después `h['x-csrf-token'] = this.csrf` si `csrf && this.csrf`, de modo que el `x-csrf-token` de otra sesión que pasa el caso «token CSRF de otra sesión» se **sobrescribe** con el token propio del cliente y la petición legítima devuelve 501. Corrección sugerida: `if (csrf && this.csrf && !('x-csrf-token' in headers) && ...)`. El mismo caso está cubierto y aprobado en mi e2e (`CSRF alterado, de otra sesión o con Origin ajeno → 403`). No se modificó `tests/security`.

## 3. Archivos creados / modificados

`packages/database`
- `prisma/schema.prisma` (modelos y enums), `prisma/migrations/20261019211004_init/` (tablas, CHECK de correo normalizado, trigger append-only), `prisma/migrations/20261019213000_audit_append_only_error_code/` (ver decisiones), `prisma/seed.ts`, `prisma.config.ts`, `src/index.ts`, `src/password.ts`, `tsconfig.json`, `.gitignore`, `package.json` (sin `type: module`, `main/types/exports`, scripts `build`/`typecheck`, dependencia `@node-rs/argon2`).

`apps/api`
- `src/main.ts`, `src/app.setup.ts`, `src/app.module.ts`; `src/config/{env,config.module}.ts`; `src/database/{prisma.service,database.module}.ts`.
- `src/common/`: `decorators/metadata.ts`, `guards/{rate-limit,authentication,csrf,validation,permissions}.guard.ts`, `filters/{error-mapper,all-exceptions.filter}.ts`, `http/{api-exception,cookies,request-context}.ts`, `rate-limit/{sliding-window-limiter,rate-limit.service,rate-limit.module}.ts`, `crypto/tokens.ts`.
- `src/modules/{auth,users,drafts,audit,health}/` (controllers, services, módulos, `draft-ownership.guard.ts`).
- Pruebas: 7 `*.spec.ts` en `src/`, y `test/{p01-auth,p02-authorization,p09-rate-limit,admin-audit}.e2e-spec.ts`, `test/support/{app,env,global-setup,global-teardown}.ts`, `test/jest-e2e.json`.
- `package.json` (scripts `typecheck`, `pre*` que reconstruyen database, `test:e2e --runInBand`, regex de Jest), `tsconfig.json` (**`strict: true`**), eliminados los archivos de la plantilla (`app.controller*`, `app.service`, `app.e2e-spec`).

Raíz: `.env.example` (todas las variables), `.env` local (ignorado, secretos aleatorios generados). `infra/compose.yml` no se modificó.

## 4. Decisiones

1. **Cliente Prisma en CommonJS.** Generador `prisma-client` con `moduleFormat = "cjs"` y `output = ../src/generated` (ignorado en Git); `packages/database` pasa a ser un paquete CJS compilado con `tsc` a `dist/` (`main`/`types`/`exports`). Lo consumen la API (CJS), Jest y el seed (`tsx`). El adaptador es `@prisma/adapter-pg` (`createPrismaAdapter`/`createPrismaClient`). Todo script que lo usa lo reconstruye antes (`prisma generate && tsc`).
2. **Argon2id en un solo sitio.** `packages/database/src/password.ts` (`hashPassword`/`verifyPassword`, m=19456, t=2, p=1) lo usan API y seed; por eso `@node-rs/argon2` se añadió también a `@alertasegura/database`. Hash señuelo generado al arrancar para las cuentas inexistentes.
3. **Trigger append-only en dos migraciones.** La primera usaba `ERRCODE = restrict_violation`; el adaptador de Prisma lo traduce a «Foreign key constraint violated» y oculta el motivo. Como esa migración ya estaba aplicada y no se debe reescribir historial ni resetear la BD, se añadió una segunda migración que redefine la función con el SQLSTATE por defecto. El trigger cubre UPDATE, DELETE (por fila) y TRUNCATE. Limitación: el propietario de la tabla o un superusuario puede eliminar el trigger; en producción la API debería conectar con un rol sin privilegios DDL.
4. **Sesiones.** Token aleatorio de 32 bytes en cookie; en BD solo SHA-256 (hex). Caducidad absoluta (480 min) e inactividad (30 min) comprobadas en cada petición; `lastSeenAt` se refresca como mucho cada 30 s. El login revoca la sesión que el navegador ya traía (rotación) y nunca adopta identificadores impuestos por el cliente. Cookie rechazada → se borran `as_session` y `as_csrf` y se audita `AUTH_SESSION_REJECTED`. Consecuencia para el cliente: tras una sesión caducada hay que volver a pedir `/auth/csrf` antes de hacer login (un 403 `CSRF_INVALID` en ese login indica refrescar el token).
5. **CSRF.** `token = <nonce>.<HMAC-SHA256(CSRF_SECRET, "session:<id>"|"anon" + "|" + nonce)>`; mismo valor en cookie HttpOnly `as_csrf` y cabecera `X-CSRF-Token`, comparación en tiempo constante; además `Origin` presente y distinto de `WEB_ORIGIN` → `CSRF_INVALID`. El contexto anónimo («pre-sesión») se liga solo a la firma, no a un identificador de pre-sesión.
6. **Orden de controles = orden de los `APP_GUARD`** (rate limit → autenticación → CSRF → validación → RBAC) y, tras ellos, el guard de propiedad de ruta. **La validación Zod es un guard (`ZodValidationGuard`), no un pipe**, porque los pipes de Nest corren después de todos los guards y el contrato exige 400 antes que 403. Los esquemas son los de `@alertasegura/shared`; los `issues` llevan ruta (`body.email`) y mensaje, nunca el valor. Toda ruta sin `@Public`, `@AnyRole` o `@RequirePermissions` se deniega (403) y se registra.
7. **Rate limiting propio en memoria** (ventana deslizante con marcas de tiempo, tope de 100 000 claves, barrido cada minuto); no se usó `@nestjs/throttler` (queda instalado pero sin uso: puede retirarse). Claves: IP global, login por IP, login por cuenta (correo normalizado), usuario. Solo las peticiones permitidas consumen cupo. **El límite por cuenta cuenta solo intentos fallidos**: un ADMIN legítimo puede iniciar sesión correctamente tantas veces como quiera (probado con 8 logins correctos con límite 3); el 6.º fallo dentro de la ventana (con el límite por defecto de 5) recibe 429 aunque la contraseña sea correcta. El límite por usuario se aplica justo después de resolver la sesión (la clave solo se conoce entonces). `RATE_LIMITED` se audita como máximo una vez por clave y minuto para que un atacante no pueda inundar la tabla.
8. **Auditoría.** `AuditService.record` captura sus propios errores (log `FALLO DE AUDITORIA …`, la respuesta no cambia) y elimina recursivamente claves que parezcan credenciales (`pass*`, `token`, `cookie`, `secret`, `authorization`, `hash`, `csrf`). Se audita también el 401 anónimo en rutas protegidas (salvo `GET /auth/me`, que la PWA consulta anónima).
9. **Errores.** Filtro global + manejador final de Express (el JSON malformado o > `BODY_LIMIT` falla en un middleware, fuera de Nest): siempre `ApiError`; 500 genérico, traza solo en el log.
10. **HTTP.** Prefijo `/api/v1`, helmet, `Cache-Control: no-store`, sin `x-powered-by`, sin CORS, límite JSON 100 kb, `trust proxy` por configuración (false por defecto), `enableShutdownHooks` + `$disconnect`.
11. **TypeScript estricto** activado en `apps/api` (`strict`, `noImplicitOverride`); sin `any` en el código de seguridad.

## 5. Variables de entorno (raíz `.env`; ejemplo en `.env.example`)

`POSTGRES_USER/PASSWORD/DB/PORT`, `DATABASE_URL` · `NODE_ENV`, `PORT`, `WEB_ORIGIN`, `CSRF_SECRET` (≥ 32 bytes, obligatorio), `COOKIE_SECURE`, `TRUST_PROXY` (`false` | entero 1–10 | `true`≡1), `BODY_LIMIT` · `SESSION_ABSOLUTE_TTL_MINUTES` (480), `SESSION_IDLE_TTL_MINUTES` (30) · `RATE_LOGIN_IP_LIMIT/WINDOW_SECONDS` (10/60), `RATE_LOGIN_ACCOUNT_LIMIT/WINDOW_SECONDS` (5/900), `RATE_USER_LIMIT/WINDOW_SECONDS` (120/60), `RATE_GLOBAL_LIMIT/WINDOW_SECONDS` (300/60) · seed: `SEED_ADMIN_EMAIL/NAME/PASSWORD`, `SEED_AUDITOR_EMAIL/PASSWORD`, `SEED_ISSUER1_EMAIL/PASSWORD`, `SEED_ISSUER2_EMAIL/PASSWORD` (sin contraseña, el usuario no se crea).

La API falla al arrancar, sin imprimir valores, si falta o es inválida alguna variable requerida.

**Puerto de PostgreSQL:** en esta máquina el 5432 ya lo ocupa un `postgres.exe` local (servicio de Windows). Mi `.env` local usa **`POSTGRES_PORT=5433`** y `DATABASE_URL=…@localhost:5433/…`. `.env.example` conserva 5432.

## 6. Comandos

```
# desde la raíz
cp .env.example .env            # y rellenar secretos, contraseñas SEED_* y CSRF_SECRET
pnpm build:packages             # shared + verification (ya compilados)
pnpm db:up                      # PostgreSQL 17 en Docker
pnpm --filter @alertasegura/database db:deploy   # migraciones (o db:migrate en desarrollo)
pnpm db:seed                    # idempotente
pnpm dev:api                    # http://localhost:3000/api/v1   (producción: pnpm --filter @alertasegura/api build && start:prod)

pnpm --filter @alertasegura/api typecheck | build | test | test:e2e
```

`test:e2e` necesita PostgreSQL arriba y `DATABASE_URL` en el `.env`; crea y elimina su propia base.

## 7. Cambios de contrato solicitados a ATLAS

- `packages/shared`: exportar los tipos `DraftResponse` y `DraftListResponse` (hoy solo existen los esquemas `DraftResponseSchema`/`DraftListResponseSchema`; la API los infiere localmente con `z.infer`).
- Documentar en `api-contract.md` que el límite de login por cuenta cuenta solo intentos fallidos y que `RATE_LIMITED` se audita una vez por clave y minuto.
- Documentar en el contrato que tras una sesión rechazada (cookie caducada) el cliente debe volver a pedir `/auth/csrf` antes del login.

## 8. Bloqueos / pendientes

- Sin bloqueos. Una restricción de Prisma impidió `migrate reset` (exige consentimiento explícito del usuario en agentes); se evitó sin destruir datos con la segunda migración (decisión 3).
- Defecto en `tests/security/g1-acceptance.mjs` (sección 2) que hace fallar P02b en la caja negra.
- Rate limiting en memoria de un solo proceso (riesgo documentado en el contrato): no se comparte entre instancias ni sobrevive a reinicios. Los fallos de login por cuenta permiten bloquear temporalmente a un usuario conocido (DoS dirigido); mitigación pendiente (p. ej. bloqueo por cuenta+IP o CAPTCHA).
- No hay limpieza periódica de sesiones caducadas ni de auditoría antigua.
- El flujo de revocación/desactivación de usuarios por API y el cambio de contraseña no están en el contrato de la semana 1.
- `@nestjs/throttler` y `@node-rs/argon2` de `apps/api` no se usan directamente (Argon2 se usa vía `@alertasegura/database`); pueden retirarse de `apps/api/package.json`.
- Publicación firmada: `POST /drafts/:id/publish` responde 501 tras todos los controles y audita `PUBLICATION_AUTHORIZED`; la firma es de la semana 2.
- `pnpm lint` (eslint con `--fix` de la plantilla) no se ejecutó ni forma parte de la entrega.

## 9. Correcciones de revisión ATLAS

Solo se tocó `apps/api` (más esta sección del informe).

1. **Lint.** `pnpm --filter @alertasegura/api format` aplicó los 338 errores de prettier. Los 13 de reglas se corrigieron sin desactivar ninguna regla:
   - `no-unnecessary-type-assertion`: eliminados `mapped!`, `as number` (x2), `[0]!`, `as string` y el cast de `getHttpServer()`;
   - `unbound-method` (2 specs): el handler se obtiene con `(Clase.prototype as Record<keyof Clase, () => void>)[nombre]`;
   - `no-unused-vars` (`env.spec.ts`): se copia el objeto y se hace `delete without.CSRF_SECRET`;
   - `no-unsafe-member-access` (p02): las respuestas se parsean con `ApiErrorSchema` y `DraftListResponseSchema`;
   - `no-base-to-string` (`audit.service.ts`): `typeof value === 'bigint' ? value.toString() : '[no serializable]'`.
   - El script `lint` ya **no usa `--fix`** (`eslint "{src,test}/**/*.ts"`); se añadió `lint:fix` aparte.
2. **Config.** `CSRF_SECRET` rechaza ahora cualquier valor que empiece por `replace-with` (sin distinguir mayúsculas ni espacios iniciales), incluido el placeholder de `.env.example`, con el mensaje «es el valor de ejemplo de .env.example». Caso nuevo en `env.spec.ts` (también comprueba que un secreto aleatorio válido sigue aceptándose).

Salida real (`apps/api`, sin parar la API de :3000 ni reconstruir `dist/`):

```
$ pnpm run lint                         -> lint exit=0      (eslint, sin --fix, 0 errores)
$ tsc --noEmit -p tsconfig.json         -> typecheck exit=0
$ tsc --noEmit -p tsconfig.build.json   -> build-check exit=0
$ jest                                  -> test exit=0
  Test Suites: 7 passed, 7 total
  Tests:       62 passed, 62 total
$ jest --config ./test/jest-e2e.json --runInBand -> e2e exit=0
  Test Suites: 4 passed, 4 total
  Tests:       77 passed, 77 total
```

Nota: para no tocar el `dist/` en ejecución ni regenerar `packages/database` (los scripts `build`/`pretest`/`pretypecheck` ejecutan `nest build` y `prisma generate`), `build` se verificó con `tsc --noEmit -p tsconfig.build.json` y las pruebas se lanzaron con `jest` directamente. `nest build` se ejecutó con éxito en la entrega anterior y el código compilado no ha cambiado de forma estructural; ejecute `pnpm --filter @alertasegura/api build` al reiniciar la API para recoger el cambio de `env.ts`.
