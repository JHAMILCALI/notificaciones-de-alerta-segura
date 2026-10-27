# Encargo FORGE — Semana 1 (backend, base de datos, seguridad del servidor)

Lee antes: `docs/coordination/README.md` (reglas y propiedad de archivos) y `docs/coordination/api-contract.md`.
Los contratos ejecutables están en `packages/shared/src` (ya compilado). **No lo modifiques**: si necesitas un cambio, explícalo en tu informe.

## Estado de partida (verificado por ATLAS)

- `apps/api`: plantilla Nest 11 recién generada (CommonJS, TS 5.9, Jest 30 + ts-jest). Carpetas de módulos vacías con `.gitkeep`.
- `packages/database`: Prisma 7.10 con `prisma.config.ts`, generador `prisma-client` (salida `generated/client`), esquema sin modelos, seed vacío, `type: module`.
- `infra/compose.yml`: servicio `postgres:17-alpine` con healthcheck. Docker Desktop está en marcha.
- No existe `.env`. Créalo a partir de `.env.example` (está en `.gitignore`), con secretos aleatorios generados localmente.
- Dependencias ya instaladas por ATLAS: api → `zod@4`, `@nestjs/throttler@6`, `@node-rs/argon2` (Argon2id probado en este Windows), `cookie-parser`, `helmet`, `@prisma/adapter-pg`, `pg` (+ tipos); database → `@prisma/adapter-pg`, `pg`, `@types/pg`, `@types/node`.
- `@alertasegura/shared` expone `require` (CJS) e `import` (ESM). La API (CJS) y Jest lo resuelven por la condición `require`.

## Tareas

1. **Base de datos (`packages/database`)**
   - Modelos: `User` (uuid, email único normalizado, displayName, passwordHash, role ADMIN|ISSUER|AUDITOR, status ACTIVE|DISABLED, createdById opcional → User, timestamps), `Session` (id, tokenHash único, userId, createdAt, lastSeenAt, expiresAt, revokedAt, ip, userAgent), `Draft` (uuid, title, body, severity, status DRAFT, ownerId → User, timestamps), `AuditLog` (uuid, occurredAt, action, outcome, actorId opcional, targetType, targetId, ip, userAgent, metadata Json). Índices adecuados.
   - Primera migración real con `prisma migrate dev`. Añade en SQL un trigger que **impida UPDATE y DELETE en `AuditLog`** (append-only) y compruébalo en una prueba.
   - Cliente: exporta desde `src/index.ts` una fábrica del `PrismaClient` con `@prisma/adapter-pg` y los tipos/enums. Debe poder consumirlo la API CommonJS y Jest (por ejemplo, generador con `moduleFormat = "cjs"` o build dual como hizo ATLAS en `packages/shared`). Decide y documenta.
   - `prisma.config.ts` y el seed deben leer el `.env` de la **raíz** del monorepo (el cwd de pnpm es `packages/database`).
   - Seed idempotente: un ADMIN inicial cuyo correo y contraseña salen de `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD` (sin valores reales en el repo), un AUDITOR y dos ISSUER opcionales con variables análogas, y borradores ficticios. Si falta una contraseña, ese usuario no se crea y el seed lo indica.
   - Ignora la carpeta del cliente generado en Git (`packages/database/.gitignore`).

2. **API (`apps/api`)**
   - Config validada con Zod al arrancar (falla rápido): `PORT`, `DATABASE_URL`, `WEB_ORIGIN`, `CSRF_SECRET` (≥ 32 bytes), `COOKIE_SECURE`, caducidades de sesión, límites de rate limiting, `TRUST_PROXY`. Carga el `.env` raíz. Actualiza `.env.example` con todas las variables y valores de ejemplo no secretos.
   - `main.ts`: prefijo `/api/v1`, `helmet`, `cookie-parser`, límite del cuerpo JSON (p. ej. 100 kb), sin `x-powered-by`, sin CORS, `trust proxy` según config, apagado limpio de Prisma.
   - Módulos: `database` (PrismaService), `auth`, `users`, `drafts`, `audit`, `health`. Guards y decoradores en `common/`.
   - Implementa exactamente el contrato: endpoints, códigos, formato `ApiError`, orden de controles, sesiones y cookies, CSRF *signed double-submit* ligado a la sesión, verificación de `Origin`, Argon2id con hash señuelo, rotación de sesión en el login, caducidad absoluta e inactividad, logout que revoca.
   - Validación con los esquemas Zod de `@alertasegura/shared` (pipe propio). `strictObject` rechaza campos extra.
   - RBAC con `ROLE_PERMISSIONS` de shared (decorador `@RequirePermissions`). Propiedad en `drafts` (otro emisor → 403).
   - `POST /drafts/:draftId/publish`: tras pasar todos los controles responde `501 PUBLICATION_NOT_IMPLEMENTED`. **No** simules la firma.
   - Rate limiting por IP y por usuario/cuenta con los límites del contrato, `Retry-After`, auditoría `RATE_LIMITED`.
   - Auditoría de: login correcto/fallido, logout, sesión rechazada, CSRF rechazado, acceso denegado (401/403), provisión de emisor, creación de borrador, publicación denegada/autorizada, rate limiting. Nunca guardes contraseñas, tokens ni cookies en `metadata`. La auditoría no debe tumbar la petición si falla, pero sí registrarse en el log.
   - Filtro global de excepciones que no filtre trazas ni detalles de Prisma.

3. **Pruebas (`apps/api`)**
   - Unitarias: hash/verificación Argon2id, matriz RBAC, CSRF (token válido, ausente, alterado, de otra sesión), guard de propiedad.
   - Integración/e2e con **PostgreSQL real** (base o esquema de pruebas aislado, migraciones aplicadas con `prisma migrate deploy`; los usuarios y contraseñas se crean en la propia prueba). Escenarios obligatorios, cada uno con su `describe` nombrado así para que ATLAS los localice:
     - `P01`: login correcto → 200, cookie con `HttpOnly` y `SameSite=Strict`, `/auth/me` devuelve rol y permisos; contraseña errónea → 401 genérico; logout → la cookie anterior deja de valer (401); hash guardado empieza por `$argon2id$`; sesión caducada → 401.
     - `P02a`: anónimo `POST /drafts/:id/publish` → 401 (con y sin token CSRF).
     - `P02b`: AUDITOR y ADMIN autenticados → 403 `FORBIDDEN`; ISSUER no propietario → 403; ISSUER propietario → 501; sin CSRF → 403 `CSRF_INVALID`.
     - `P09`: superar el límite de login por cuenta y por IP → 429 con `Retry-After`; superar el límite por usuario autenticado → 429. Usa límites bajos inyectados por config en la prueba.
     - Además: provisión de emisor solo por ADMIN, entrada inválida → 400, auditoría registrada y append-only.
   - Scripts: `test`, `test:e2e`, `typecheck` (`tsc --noEmit`), `build`.

## Fuera de alcance

Firmante aislado, publicación firmada, ciclo de vida completo de alertas, PWA final. No toques `apps/signer`, `tools/trust-cli`, `apps/web`, `packages/verification`, `packages/shared`.

## Entrega

Escribe `docs/coordination/forge-report.md` con: archivos creados/modificados, decisiones (formato del cliente Prisma, almacenamiento del rate limiting, etc.), variables de entorno, comandos para levantar todo, **salida real** de `typecheck`, `build`, `test` y `test:e2e`, y una sección «Bloqueos / pendientes». No hagas commits.
