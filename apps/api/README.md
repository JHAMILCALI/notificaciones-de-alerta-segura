# @alertasegura/api

API modular de AlertaSegura construida con NestJS.

- `src/common`: guards, decoradores, filtros e interceptores transversales.
- `src/config`: carga y validación de configuración.
- `src/database`: integración de `@alertasegura/database`.
- `src/modules`: módulos funcionales de identidad, alertas, confianza y auditoría.

Cada caso de uso incorporará su controller, service, DTO y pruebas cuando corresponda; no se crean capas vacías por adelantado.

Ejecutar desde la raíz con `pnpm dev:api`.
