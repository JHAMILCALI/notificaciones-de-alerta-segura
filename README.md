# AlertaSegura

Monorepo con React + Vite para la PWA, NestJS para la API, PostgreSQL con Prisma y un proceso aislado para la firma digital.

## Requisitos

- Node.js 24.11 o superior
- pnpm 12
- Docker con Docker Compose (Docker Desktop en marcha)

## Ejecución local

```bash
pnpm install
cp .env.example .env        # rellena CSRF_SECRET y las contraseñas SEED_* (ver abajo)
pnpm build:packages         # compila shared y verification (las apps los importan desde dist)
pnpm db:up                  # PostgreSQL 17 en Docker, espera al healthcheck
pnpm db:deploy              # aplica las migraciones
pnpm db:seed                # ADMIN, AUDITOR y dos emisores de laboratorio (idempotente)
pnpm dev                    # API en http://localhost:3000/api/v1 y PWA en http://localhost:5173
```

Abre `http://localhost:5173`. Vite redirige `/api` a la API, así que el navegador ve un único origen y no hace falta CORS.

### Variables de entorno

`.env` está ignorado por Git. Genera los secretos localmente, por ejemplo:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"   # CSRF_SECRET
```

- `SEED_ADMIN_PASSWORD`, `SEED_AUDITOR_PASSWORD`, `SEED_ISSUER1_PASSWORD`, `SEED_ISSUER2_PASSWORD`: mínimo 12 caracteres. Si una falta, ese usuario no se crea.
- Si el puerto 5432 está ocupado (p. ej. por un PostgreSQL instalado en Windows), cambia `POSTGRES_PORT` y el puerto de `DATABASE_URL` (p. ej. 5433).
- `COOKIE_SECURE=true` es obligatorio detrás de HTTPS: activa `Secure` y el prefijo `__Host-` en las cookies.
- `RATE_*` y `SESSION_*` ajustan los límites y caducidades (valores por defecto en `docs/coordination/api-contract.md`).

## Verificación

```bash
pnpm typecheck              # todo el monorepo
pnpm build
pnpm test                   # unitarias: api (Jest), web y verification (Vitest)
pnpm test:e2e               # API contra PostgreSQL real (crea y borra su propia base)
pnpm --filter @alertasegura/verification vectors   # regenera los vectores P13 con una clave efímera
pnpm test:g1                # aceptación G1 de caja negra contra la API en marcha
pnpm test:browser           # complementaria: recorrido en Google Chrome real (requiere Chrome instalado y pnpm dev)
pnpm test:cleanup           # simulación de limpieza de borradores de prueba; `pnpm test:cleanup -- --apply` los borra
```

Resultados y evidencias de la semana 1: [`docs/evidence/semana1-cumplimiento.md`](docs/evidence/semana1-cumplimiento.md).

## Proyectos

- `apps/web`: interfaz React, rutas y funciones PWA. Es el único frontend (`apps/frontend` no se usa).
- `apps/api`: API NestJS, autenticación, permisos, alertas y auditoría.
- `apps/signer`: proceso aislado que será el único consumidor de la clave privada.
- `packages/database`: esquema, migraciones y semilla de Prisma.
- `packages/shared`: contratos de datos compartidos (Zod), en ESM y CommonJS.
- `packages/verification`: canonicalización JCS (RFC 8785) y verificación ECDSA P-256 con Web Crypto.
- `tools/trust-cli`: administración de claves, manifiestos y revocación.

## Módulos de seguridad

| Módulo | Implementación | Estado semana 1 |
| --- | --- | --- |
| M1. Identidad y acceso | `apps/api/src/modules/auth`, `users`, `common/guards` | Implementado: Argon2id, sesiones, CSRF, RBAC, propiedad, rate limiting |
| M2. Ciclo de vida | `apps/api/src/modules/drafts` y `alerts` | Borradores mínimos y autorización de publicación (501 hasta la firma) |
| M3. Firma y claves | `apps/api/src/modules/trust`, `apps/signer` y `tools/trust-cli` | Semana 2 |
| M4. Verificador PWA | `apps/web/src/features/verification` y `packages/verification` | JCS + verificación Web Crypto y laboratorio; PWA final en semanas posteriores |
| M5. Auditoría | `apps/api/src/modules/audit` | Implementado: registro append-only con trigger |

La API y la PWA no deben leer la clave privada. El firmante se ejecutará con usuario, red y montaje de secreto separados; la PWA solo recibirá material público para verificar firmas mediante Web Crypto.

## Documentación

[Arquitectura](docs/architecture/README.md) · [Base de datos](docs/database/README.md) · [Modelo de amenazas](docs/threat-model/README.md) · [Contrato API](docs/coordination/api-contract.md) · [Coordinación](docs/coordination/README.md)
