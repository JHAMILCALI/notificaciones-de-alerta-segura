# Base de datos

PostgreSQL 17 en Docker (`infra/compose.yml`), esquema gestionado con Prisma 7 (`packages/database/prisma/schema.prisma`)
y migraciones SQL versionadas en `packages/database/prisma/migrations`. El cliente se genera en CommonJS dentro de
`packages/database/src/generated` (ignorado en Git) y se conecta mediante `@prisma/adapter-pg`.

## Modelo (semana 1)

```text
            createdById (SET NULL)
          ┌───────────────┐
          ▼               │
┌──────────────────┐      │      ┌───────────────────────┐
│ User             │──────┘      │ Session               │
│ id uuid PK       │1───────────*│ id uuid PK            │
│ email UNIQUE     │  (CASCADE)  │ tokenHash UNIQUE      │  SHA-256 del token; nunca el token
│ displayName      │             │ userId FK → User      │
│ passwordHash     │  Argon2id   │ createdAt, lastSeenAt │  inactividad
│ role  enum       │             │ expiresAt             │  caducidad absoluta
│ status enum      │             │ revokedAt?            │  logout / rotación
│ createdById? FK  │             │ ip?, userAgent?       │
│ createdAt        │             └───────────────────────┘
│ updatedAt        │
└──────────────────┘1──────────*┌───────────────────────┐
                     (RESTRICT) │ Draft                 │
                                │ id uuid PK            │
                                │ title, body           │
                                │ severity enum         │
                                │ status enum (DRAFT)   │
                                │ ownerId FK → User     │  autorización por propiedad
                                │ createdAt, updatedAt  │
                                └───────────────────────┘

┌───────────────────────────────┐
│ AuditLog  (append-only)       │  sin FK a User a propósito: la evidencia sobrevive a cambios en usuarios
│ id uuid PK, occurredAt        │
│ action, outcome enum          │
│ actorId?, targetType?, targetId?
│ ip?, userAgent?, metadata jsonb│  nunca contraseñas, tokens ni cookies
└───────────────────────────────┘
```

Enums: `Role` (ADMIN, ISSUER, AUDITOR), `UserStatus` (ACTIVE, DISABLED), `Severity` (INFO, WARNING, CRITICAL),
`DraftStatus` (DRAFT; el resto de estados llega con el ciclo de vida de la semana 2), `AuditOutcome` (SUCCESS, DENIED, FAILURE).

## Invariantes de integridad

| Invariante | Dónde se impone |
| --- | --- |
| Correo único y normalizado | `UNIQUE` + `CHECK (email = lower(btrim(email)))` (`User_email_normalized_chk`) |
| Solo el hash del token de sesión en BD | `Session.tokenHash UNIQUE`; la API guarda `sha256(token)` |
| Borrar un usuario borra sus sesiones | FK `Session.userId ON DELETE CASCADE` |
| No se borra un emisor con borradores | FK `Draft.ownerId ON DELETE RESTRICT` |
| Auditoría inmutable | Triggers `AuditLog_no_update_delete` (fila) y `AuditLog_no_truncate` (sentencia) que lanzan `audit_log_append_only` |
| Contraseñas con Argon2id | `passwordHash` siempre empieza por `$argon2id$` (comprobado en e2e P01) |

## Índices

`Session(userId, revokedAt)` y `Session(expiresAt)` para resolver y purgar sesiones; `Draft(ownerId, createdAt DESC)` para
«mis borradores»; `AuditLog(occurredAt DESC)`, `(action, occurredAt DESC)` y `(actorId, occurredAt DESC)` para consultas de auditoría.

## Migraciones

| Migración | Contenido |
| --- | --- |
| `20261019211004_init` | Tablas, enums, índices, FKs, CHECK del correo y triggers append-only |
| `20261019213000_audit_append_only_error_code` | Redefine la función del trigger para que el error no se confunda con una violación de FK en Prisma |

Comandos (desde la raíz): `pnpm db:up`, `pnpm db:deploy` (aplica migraciones), `pnpm db:seed`, `pnpm db:migrate` (solo desarrollo, crea nuevas).

## Seed

Idempotente: crea el ADMIN, el AUDITOR y dos ISSUER si existen sus variables `SEED_*_EMAIL` y `SEED_*_PASSWORD` en el `.env`
raíz (ignorado en Git), y borradores ficticios. Si falta una contraseña, ese usuario no se crea. Ninguna contraseña está en el repositorio.

## Permisos SQL y riesgos pendientes

En la semana 1 la API usa el usuario propietario de la base creado por Docker. Pendiente (semana 2): un rol de aplicación
sin `TRUNCATE`/DDL, con `INSERT, SELECT` únicamente sobre `AuditLog`, separado del rol de migraciones. El trigger ya impide
la modificación incluso con el rol propietario, salvo que se deshabilite explícitamente el trigger (requiere DDL).
