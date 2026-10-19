# Arquitectura

AlertaSegura se mantiene como un monorepo pnpm sin el modo monorepo propio de NestJS. React y NestJS siguen siendo proyectos independientes y reutilizan paquetes con dependencias `workspace:*`.

## Flujo principal

1. `apps/web` consume la API REST de `apps/api`.
2. La API aplica autenticación, permisos y reglas de ciclo de vida.
3. `apps/signer` es el único proceso autorizado para usar la clave privada.
4. `packages/verification` verifica firmas con material público en la PWA.
5. `packages/database` administra el esquema y las migraciones PostgreSQL.

El proceso firmante no comparte identidad, permisos ni montaje de secretos con la API o la PWA.
