# Coordinación multiagente — Semana 1

| Agente | Modelo | Responsabilidad |
| --- | --- | --- |
| ATLAS | Opus 5.5 | Arquitectura, contratos, documentación, revisión, integración y aceptación G1 |
| FORGE | Sonnet 5.5 | Backend NestJS, Prisma, PostgreSQL y seguridad del servidor |
| CIPHER | Sonnet 5.5 | Frontend React/Vite y criptografía con Web Crypto |

Mecanismo real: ATLAS lanza a FORGE y CIPHER como subagentes de Claude Code desde la misma sesión.
Cada uno recibe su encargo (`forge-semana1.md`, `cipher-semana1.md`) y entrega un informe con evidencias.
ATLAS revisa, devuelve correcciones y ejecuta las pruebas de aceptación.

## Propiedad de archivos

| Ruta | Propietario | Otros agentes |
| --- | --- | --- |
| `packages/shared/**` | ATLAS | Solo lectura. Un cambio de contrato se solicita a ATLAS. |
| `docs/**` (salvo lo indicado), `README.md`, `package.json` raíz | ATLAS | Solo lectura |
| `tests/security/**` | ATLAS | Solo lectura |
| `apps/api/**`, `packages/database/**`, `infra/compose.yml`, `.env.example` | FORGE | Solo lectura |
| `docs/coordination/forge-report.md` | FORGE | — |
| `apps/web/**`, `packages/verification/**`, `tests/fixtures/crypto/**` | CIPHER | Solo lectura |
| `docs/coordination/cipher-report.md` | CIPHER | — |
| `apps/signer/**`, `tools/trust-cli/**` | Nadie (semana 2) | No modificar |
| `apps/frontend/` | Nadie | Carpeta vacía y no versionada; `apps/web` es el frontend único. No crear otro. |

## Reglas

1. Contratos en `packages/shared` (`docs/coordination/api-contract.md`). Nadie los cambia sin pasar por ATLAS.
2. Dependencias: ATLAS ya instaló las conocidas. Si un agente necesita otra, la añade con
   `pnpm --filter <su-paquete> add <dep>` y la lista en su informe. Nunca `pnpm install` en la raíz
   mientras otro agente instala: si pnpm falla por el lockfile, reintentar una vez y reportar.
3. Sin secretos en Git: contraseñas y claves salen de `.env` (ignorado) o se generan en las pruebas.
   Las claves ECDSA de laboratorio son efímeras; en el repositorio solo hay claves públicas y firmas.
4. TypeScript estricto. Nada de `any` en código de seguridad; nada de desactivar comprobaciones para que pase una prueba.
5. Ninguna implementación ficticia: si algo es de la semana 2 (firmante aislado, publicación firmada),
   el endpoint lo declara con `501 PUBLICATION_NOT_IMPLEMENTED`.
6. Antes de entregar: `typecheck`, `build` y pruebas del paquete propio en verde, con la salida en el informe.
7. Un bloqueo se reporta en el informe en una sección «Bloqueos», sin inventar la solución.
8. No commits: ATLAS integra y confirma.
