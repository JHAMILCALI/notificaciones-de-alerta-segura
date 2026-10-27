# Contrato API — Semana 1

Fuente de verdad ejecutable: `@alertasegura/shared` (esquemas Zod). Este documento la resume.
El paquete se publica en dos formatos: ESM (`import`, para Vite) y CommonJS (`require`, para NestJS y Jest).
Tras cambiar `packages/shared/src` hay que ejecutar `pnpm --filter @alertasegura/shared build`.

## Topología local

| Componente | URL |
| --- | --- |
| PWA (Vite) | `http://localhost:5173` |
| API (NestJS) | `http://localhost:3000`, prefijo global `/api/v1` |
| PostgreSQL 17 (Docker) | `localhost:5432` |

Vite redirige `/api` a `http://localhost:3000` (`server.proxy`). El navegador ve un único origen, así que no se habilita CORS.
El cliente siempre usa rutas relativas (`/api/v1/...`) con `credentials: 'same-origin'`.

## Roles y permisos (`ROLE_PERMISSIONS`)

| Rol | Permisos |
| --- | --- |
| ADMIN | `users:read`, `issuers:provision`, `audit:read` |
| ISSUER | `drafts:create`, `drafts:read-own`, `alerts:publish` |
| AUDITOR | `audit:read` |

Ciudadanos: anónimos, solo rutas públicas. No hay autorregistro; solo ADMIN crea emisores.
Publicar exige `alerts:publish` **y** ser propietario del borrador.

## Sesión y CSRF

- Login correcto: sesión en servidor (tabla `Session`; en la cookie va un token aleatorio de 32 bytes y en BD solo su SHA-256).
- Cookie de sesión `as_session` (`__Host-as_session` con `COOKIE_SECURE=true`): `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` bajo HTTPS.
  Caducidad absoluta (8 h) e inactividad (30 min), configurables. Logout revoca la fila y borra la cookie. El login rota la sesión.
- CSRF: *signed double-submit* (OWASP). `GET /auth/csrf` fija la cookie HttpOnly `as_csrf` y devuelve `csrfToken`.
  El cliente lo envía en la cabecera `X-CSRF-Token` en todo POST/PUT/PATCH/DELETE, login incluido.
  El token está ligado a la sesión (o a la pre-sesión anónima) mediante HMAC con `CSRF_SECRET`.
  El login devuelve un `csrfToken` nuevo; tras el logout el cliente pide otro.
  Además se rechaza un `Origin` presente y distinto de `WEB_ORIGIN`.
- Una sesión rechazada (caducada, revocada, desconocida) borra las cookies `as_session` y `as_csrf`:
  el cliente debe pedir de nuevo `GET /auth/csrf` antes de iniciar sesión o recibirá `403 CSRF_INVALID`
  (el cliente de `apps/web` lo hace solo al reintentar una vez tras `CSRF_INVALID`).

## Orden de los controles en rutas protegidas

1. Rate limiting → `429 RATE_LIMITED` con cabecera `Retry-After`
2. Autenticación → `401 UNAUTHENTICATED` (con o sin token CSRF: un anónimo **siempre** recibe 401 en rutas protegidas)
3. CSRF (métodos no seguros) → `403 CSRF_INVALID`
4. Validación Zod → `400 VALIDATION_FAILED`
5. RBAC → `403 FORBIDDEN`
6. Propiedad → `403 FORBIDDEN` (`404 NOT_FOUND` si el recurso no existe)

En rutas públicas no seguras (`POST /auth/login`) el CSRF se aplica sin autenticación previa.

## Endpoints

| Método y ruta | Acceso | Cuerpo | Respuestas |
| --- | --- | --- | --- |
| `GET /health` | público | — | 200/503 `HealthResponse` |
| `GET /auth/csrf` | público | — | 200 `CsrfResponse` |
| `POST /auth/login` | público + CSRF | `LoginRequest` | 200 `LoginResponse`; 401 `INVALID_CREDENTIALS` (mensaje genérico, también para cuentas DISABLED); 403 `CSRF_INVALID`; 429 |
| `POST /auth/logout` | sesión + CSRF | — | 204 |
| `GET /auth/me` | sesión | — | 200 `MeResponse`; 401 |
| `GET /admin/users` | `users:read` | — | 200 `UserListResponse` |
| `POST /admin/issuers` | `issuers:provision` + CSRF | `ProvisionIssuerRequest` | 201 `{ user }`; 409 `CONFLICT` si el correo existe |
| `POST /drafts` | `drafts:create` + CSRF | `CreateDraftRequest` | 201 `DraftResponse` |
| `GET /drafts` | `drafts:read-own` | — | 200 `DraftListResponse` (solo propios) |
| `GET /drafts/:draftId` | `drafts:read-own` + propiedad | — | 200 `DraftResponse`; 403; 404 |
| `POST /drafts/:draftId/publish` | `alerts:publish` + propiedad + CSRF | — | 401 / 403 / 404; si todo se cumple **501 `PUBLICATION_NOT_IMPLEMENTED`** (la firma es de la semana 2) y se audita `PUBLICATION_AUTHORIZED` |
| `GET /audit?limit=` | `audit:read` | — | 200 `AuditListResponse`, más recientes primero |

Todos los errores siguen `ApiError` (`statusCode`, `code`, `message`, `issues?`). Nunca se devuelven trazas ni `passwordHash`.

## Rate limiting (valores por defecto, configurables por entorno)

| Ámbito | Clave | Límite |
| --- | --- | --- |
| Login por IP | IP | 10 / 60 s |
| Login por cuenta | correo normalizado | 5 / 15 min |
| API autenticada | id de usuario | 120 / 60 s |
| Global | IP | 300 / 60 s |

- El límite por cuenta cuenta **solo intentos fallidos**: un usuario legítimo no se bloquea por iniciar sesión varias veces.
  Con el cupo agotado la contraseña ni siquiera se verifica.
- `RATE_LIMITED` se audita como máximo una vez por clave y minuto, para que un ataque no inunde `AuditLog`.

Almacenamiento en memoria del proceso (una instancia en la semana 1; riesgo documentado).
`TRUST_PROXY` desactivado por defecto: la IP es la del socket y no se confía en `X-Forwarded-For`.

## Contraseñas

Argon2id (`@node-rs/argon2`), m=19456 KiB, t=2, p=1 (mínimo OWASP). Nuevas contraseñas de 12 a 128 caracteres.
Si el correo no existe se verifica contra un hash señuelo para no revelar cuentas por tiempo de respuesta.

## Criptografía (P13)

- Canonicalización: JCS, RFC 8785 → `canonicalize(value): string` en `@alertasegura/verification`.
- Firma: ECDSA P-256 sobre SHA-256 de los bytes UTF-8 del JSON canónico.
  Formato de firma en el cable: IEEE P1363 (`r‖s`, 64 bytes) en base64url. Node debe firmar con `dsaEncoding: 'ieee-p1363'`.
- Clave pública: JWK (`kty: EC`, `crv: P-256`, `x`, `y`), con `kid` = huella SHA-256 base64url de la SPKI DER.
- Vectores: `tests/fixtures/crypto/p13-vectors.json`, generados en Node con una clave efímera que se descarta.
