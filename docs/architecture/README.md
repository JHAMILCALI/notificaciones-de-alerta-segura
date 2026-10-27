# Arquitectura

AlertaSegura se mantiene como un monorepo pnpm sin el modo monorepo propio de NestJS. React y NestJS siguen siendo proyectos independientes y reutilizan paquetes con dependencias `workspace:*`.

## Componentes

```text
 Navegador (ciudadano / personal)
 └─ apps/web  React 19 + Vite 8 ──── /api (proxy Vite, mismo origen) ────┐
      └─ packages/verification  JCS + ECDSA P-256 con Web Crypto         │
                                                                         ▼
                                     apps/api  NestJS 11 (/api/v1)
                                     ├─ auth      login, logout, sesiones, CSRF
                                     ├─ users     provisión de emisores (ADMIN)
                                     ├─ drafts    borradores + propiedad + publish (501 en S1)
                                     ├─ audit     registro append-only
                                     └─ health
                                                │ Prisma 7 + adapter-pg
                                                ▼
                                     PostgreSQL 17 (Docker, infra/compose.yml)

 apps/signer  (semana 2) proceso aislado, único con acceso a la clave privada, red interna sin salida
 tools/trust-cli (semana 2) administración de claves, manifiestos y revocación
 packages/shared  contratos Zod, roles/permisos, códigos de error (ESM + CJS)
```

## Flujo principal

1. `apps/web` consume la API REST de `apps/api` mediante rutas relativas `/api/v1`; en desarrollo Vite actúa de proxy, por lo que no hay CORS.
2. La API aplica, en este orden: rate limiting, autenticación, CSRF, validación, RBAC y propiedad.
3. `apps/signer` es el único proceso autorizado para usar la clave privada (semana 2).
4. `packages/verification` verifica firmas con material público en la PWA.
5. `packages/database` administra el esquema y las migraciones PostgreSQL.

El proceso firmante no comparte identidad, permisos ni montaje de secretos con la API o la PWA.

## Decisiones de la semana 1

| Decisión | Motivo |
| --- | --- |
| Sesiones en servidor con token opaco en cookie HttpOnly (no JWT) | Revocación inmediata en logout; el token no es legible desde JavaScript; en BD solo se guarda su SHA-256 |
| `SameSite=Strict` + CSRF *signed double-submit* + comprobación de `Origin` | Defensa en profundidad: SameSite no cubre subdominios ni navegadores antiguos |
| Autenticación antes que CSRF en rutas protegidas | Un anónimo recibe siempre 401 (P02a), y no se revela nada sobre el token |
| ADMIN sin permiso de publicación | Separación de funciones: quien crea cuentas no publica alertas |
| Publicación = permiso `alerts:publish` **y** propiedad del borrador | Evita IDOR entre emisores |
| `POST /drafts/:id/publish` responde 501 tras autorizar | La firma real llega con el firmante aislado (semana 2); no se simula |
| Contratos Zod en `packages/shared`, compilados en ESM y CJS | Un único esquema valida en la API (CJS/Jest) y en la PWA (Vite/ESM) |
| Argon2id m=19456 KiB, t=2, p=1 (`@node-rs/argon2`) | Mínimo recomendado por OWASP; binario precompilado sin scripts de instalación |
| Rate limiting en memoria del proceso | Suficiente con una instancia; pasar a un almacén compartido si se escala (riesgo R-03) |
| Firma P1363 (`r‖s`) en base64url sobre JCS (RFC 8785) | Es el formato nativo de Web Crypto; Node lo produce con `dsaEncoding: 'ieee-p1363'` |

Contrato detallado: [`docs/coordination/api-contract.md`](../coordination/api-contract.md).
Modelo de datos: [`docs/database`](../database/README.md). Amenazas: [`docs/threat-model`](../threat-model/README.md).
