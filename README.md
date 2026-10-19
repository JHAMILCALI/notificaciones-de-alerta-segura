# AlertaSegura

Monorepo con React + Vite para la PWA, NestJS para la API, PostgreSQL con Prisma y un proceso aislado para la firma digital.

## Requisitos

- Node.js 24.11 o superior
- pnpm 12
- Docker con Docker Compose

## Primeros pasos

```bash
pnpm install
pnpm db:up
pnpm dev
```

Copia `.env.example` a `.env` y cambia las credenciales antes de iniciar los servicios.

## Proyectos

- `apps/web`: interfaz React, rutas y funciones PWA.
- `apps/api`: API NestJS, autenticación, permisos, alertas y auditoría.
- `apps/signer`: proceso aislado que será el único consumidor de la clave privada.
- `packages/database`: esquema, migraciones y semilla de Prisma.
- `packages/shared`: contratos de datos compartidos.
- `packages/verification`: verificación pública reutilizable en la PWA.
- `tools/trust-cli`: administración de claves, manifiestos y revocación.

La estructura inicial delimita responsabilidades. Los módulos de seguridad aún no implementados contienen marcadores explícitos y no deben considerarse controles terminados.

## Módulos de seguridad

| Módulo | Implementación prevista |
| --- | --- |
| M1. Identidad y acceso | `apps/api/src/modules/auth`, `users` y guards |
| M2. Ciclo de vida | `apps/api/src/modules/drafts` y `alerts` |
| M3. Firma y claves | `apps/api/src/modules/trust`, `apps/signer` y `tools/trust-cli` |
| M4. Verificador PWA | `apps/web/src/features/verification` y `packages/verification` |
| M5. Auditoría | `apps/api/src/modules/audit` |

La API y la PWA no deben leer la clave privada. El firmante se ejecutará con usuario, red y montaje de secreto separados; la PWA solo recibirá material público para verificar firmas mediante Web Crypto.
