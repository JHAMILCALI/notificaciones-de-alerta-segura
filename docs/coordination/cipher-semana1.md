# Encargo CIPHER — Semana 1 (frontend React y criptografía Web Crypto)

Lee antes: `docs/coordination/README.md` (reglas y propiedad de archivos) y `docs/coordination/api-contract.md`.
Los contratos ejecutables están en `packages/shared/src` (ya compilado). **No lo modifiques**: si necesitas un cambio, explícalo en tu informe.

## Estado de partida (verificado por ATLAS)

- `apps/web` es el frontend único: plantilla Vite 8 + React 19 + TS 6 sin tocar (contador de ejemplo). Carpetas `features/*`, `pages`, `lib`, etc. vacías.
- `apps/frontend` está vacío y no versionado: **ignóralo**.
- `packages/verification`: ESM, `sha256` y `verifyEcdsa` mínimos; `canonicalize` lanza «pendiente».
- Dependencias ya instaladas por ATLAS: web → `react-router@7`, `vitest@5`, `jsdom`, `@testing-library/react`, `@testing-library/jest-dom`, `@testing-library/user-event`; verification → `vitest@5`, `@types/node`.
- FORGE construye la API en paralelo. Trabaja contra el contrato; en pruebas unitarias simula `fetch`. ATLAS hará la integración con la API real.

## Tareas

1. **`packages/verification`**
   - `canonicalize(value): string` conforme a **RFC 8785**: orden de claves por unidades de código UTF-16, serialización de números según ECMAScript (`-0` → `0`, notación exponencial donde corresponda), escape mínimo de cadenas, rechazo de `NaN`/`Infinity`, `undefined`, funciones, `BigInt`, símbolos, ciclos y surrogates sueltos (I-JSON). Sin dependencias externas.
   - Utilidades: `utf8`, base64url ⇄ bytes, `importPublicKeyJwk` (solo `verify`, `extractable: false`; rechaza JWK que traiga `d`), `verifyCanonicalSignature({ payload, signatureB64u, publicKeyJwk })` que canonicaliza, codifica en UTF-8 y verifica con `crypto.subtle` (ECDSA P-256, SHA-256, firma P1363 de 64 bytes). Una firma con longitud incorrecta o base64url inválido devuelve `false` o un error tipado; nunca `true`.
   - Pruebas (vitest): vectores del RFC 8785 (como mínimo los ejemplos de números y el ejemplo de ordenación de claves del RFC), casos de rechazo, ida y vuelta base64url.
   - Script de vectores `scripts/generate-p13-vectors.ts`: en Node genera un par de claves **efímero** con `node:crypto`, firma varios documentos canonicalizados con `dsaEncoding: 'ieee-p1363'`, y escribe `tests/fixtures/crypto/p13-vectors.json` con la clave pública JWK + `kid`, cada documento, su forma canónica, SHA-256 y firma. **La clave privada nunca se escribe en disco.**
   - Prueba de interoperabilidad `P13`: (a) cada vector se verifica con Web Crypto; (b) contenido alterado (un campo cambiado, una clave añadida, un bit de la firma, otra clave pública) se rechaza; (c) en la propia prueba, firma en Node con `node:crypto` y verifica con `crypto.subtle`, y al revés, firma con Web Crypto y verifica con `node:crypto`. Usa `describe('P13 ...')`.
   - Scripts: `build`, `typecheck`, `test`, `vectors`.

2. **`apps/web`**
   - Sustituye la plantilla de ejemplo (elimina los recursos que dejen de usarse).
   - Proxy de Vite `/api` → `http://localhost:3000`. Configuración de vitest con jsdom.
   - Cliente API en `src/lib/api.ts`: rutas relativas, `credentials: 'same-origin'`, obtiene y guarda en memoria el token CSRF (`GET /auth/csrf`, el que devuelve el login, uno nuevo tras logout), lo envía en `X-CSRF-Token`, reintenta una vez si recibe `CSRF_INVALID`, valida las respuestas con los esquemas Zod de shared y convierte los errores en un tipo `ApiError`. Nada de tokens en `localStorage`/`sessionStorage`.
   - Sesión: `AuthProvider` que consulta `/auth/me` al cargar; estados cargando / anónimo / autenticado; logout.
   - Rutas (react-router 7): `/` inicio y consulta ciudadana (pública, informa de que la consulta de alertas firmadas llegará más adelante), `/login`, `/panel` protegida (redirige a `/login` si 401) que muestra usuario, rol y permisos y, según permisos, enlaces a `/panel/usuarios` (ADMIN, lista `GET /admin/users`), `/panel/borradores` (ISSUER, lista y creación básica), `/panel/auditoria` (ADMIN/AUDITOR, `GET /audit`). Las comprobaciones de rol en el frontend son solo de interfaz.
   - `/laboratorio/criptografia`: verifica en el navegador los vectores de `p13-vectors.json` con `@alertasegura/verification` y permite alterar el contenido para ver el rechazo. Evidencia visual de P13.
   - Login: formulario accesible (labels, `autocomplete`), mensaje genérico de credenciales incorrectas, mensaje claro para 429 (usando `Retry-After`), botón deshabilitado mientras envía.
   - Interfaz limpia y adaptable (móvil ≥ 360 px y escritorio), CSS propio sin frameworks; prioriza función y accesibilidad sobre estética.
   - Pruebas (vitest + Testing Library): formulario de login (éxito, 401, 429), ruta protegida que redirige, cliente API que envía `X-CSRF-Token` y reintenta tras `CSRF_INVALID`.
   - Scripts: `dev`, `build`, `typecheck`, `test`, `lint`.

## Restricciones

- **Ninguna clave privada en el frontend ni en el repositorio**. Solo claves públicas y firmas de laboratorio.
- Sin `dangerouslySetInnerHTML`. Sin secretos en variables `VITE_*`.
- No implementes el módulo de alertas ciudadanas ni la PWA de verificación final (service worker, manifiesto offline).
- No toques `apps/api`, `packages/database`, `packages/shared`, `apps/signer`, `tools/trust-cli`.

## Entrega

Escribe `docs/coordination/cipher-report.md` con: archivos creados/modificados, decisiones (implementación JCS, formato de firma, gestión de CSRF), comandos, **salida real** de `typecheck`, `build`, `test` y del generador de vectores, y una sección «Bloqueos / pendientes». No hagas commits.
