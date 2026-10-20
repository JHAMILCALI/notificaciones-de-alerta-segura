# Informe CIPHER — Semana 1

Estado: `packages/verification` y `apps/web` completos contra el contrato. `typecheck`, `build`, `test`, `lint` y el generador de vectores se ejecutaron y pasan. La API real de FORGE no estaba disponible: el frontend se probó con `fetch` simulado y con el proxy de Vite (ver «Bloqueos / pendientes»).

## Archivos

### `packages/verification` (ESM, sin dependencias externas)
- `src/canonicalize.ts` — `canonicalize(value): string` (RFC 8785).
- `src/errors.ts` — `CanonicalizationError` y `VerificationError` con campo `code`.
- `src/base64url.ts` — `bytesToBase64Url` / `base64UrlToBytes` (estricto, ver decisiones).
- `src/hash.ts` — `sha256`, `sha256Hex`, `sha256Base64Url`, `utf8`, `bytesToHex`.
- `src/verify.ts` — `verifyEcdsa` (existente), `importPublicKeyJwk`, `computeKid`, `verifyCanonicalSignature`, `P1363_SIGNATURE_LENGTH`.
- `src/index.ts` — exportaciones públicas.
- `scripts/generate-p13-vectors.ts` — generador de vectores (clave efímera).
- `test/canonicalize.test.ts`, `test/base64url.test.ts`, `test/p13-interop.test.ts`.
- `tsconfig.json` (typecheck de src+test+scripts, `noEmit`), `tsconfig.build.json` (solo `src` → `dist`), `vitest.config.ts`, `package.json` (scripts `build`, `dev`, `typecheck`, `test`, `vectors`).
- Sustituidos: `canonicalize.ts`, `hash.ts`, `verify.ts`, `index.ts`, `tsconfig.json`, `package.json`.

### `tests/fixtures/crypto/`
- `p13-vectors.json` — generado por `pnpm --filter @alertasegura/verification vectors`. Contiene la JWK pública (+`kid`), 5 documentos, su forma canónica, SHA-256 (hex) y firma P1363 base64url. Sin clave privada (comprobado: ninguna aparición de `"d"` ni `PRIVATE`). Se regenera con una clave nueva en cada ejecución; las pruebas leen el archivo actual, así que cualquier regeneración es válida.

### `apps/web`
- Configuración: `vite.config.ts` (proxy `/api` → `http://localhost:3000`, puerto 5173 estricto, también en `preview`; bloque `test` con jsdom), `index.html` (`lang="es"`), `tsconfig.app.json` (+`resolveJsonModule`, `strict`), `package.json` (scripts `dev`, `build`, `typecheck`, `test`, `lint`, `preview`), `public/favicon.svg` nuevo.
- Eliminados (plantilla): `src/App.tsx`, `src/App.css`, `src/index.css`, `src/assets/*`, `public/icons.svg`, los `.gitkeep` de carpetas que ahora tienen contenido.
- `src/main.tsx`, `src/styles.css` (CSS propio, claro/oscuro, ≥ 360 px).
- `src/app/App.tsx`, `src/app/AppRoutes.tsx` — router.
- `src/lib/api.ts` (cliente + `ApiError`), `src/lib/api-context.ts` (cliente inyectable).
- `src/features/auth/`: `AuthProvider.tsx`, `auth-context.ts`, `ProtectedRoute.tsx`, `LoginPage.tsx`, `login-messages.ts`.
- `src/features/dashboard/`: `DashboardPage.tsx`, `UsersPage.tsx`, `DraftsPage.tsx`. `src/features/audit/AuditPage.tsx`.
- `src/features/verification/`: `lab.ts`, `CryptoLabPage.tsx`.
- `src/pages/HomePage.tsx`, `src/pages/NotFoundPage.tsx`, `src/components/Layout.tsx`, `src/hooks/useResource.ts`.
- Pruebas: `src/lib/api.test.ts`, `src/features/auth/LoginPage.test.tsx`, `src/features/auth/ProtectedRoute.test.tsx`, `src/features/dashboard/DraftsPage.test.tsx`, `src/features/verification/CryptoLabPage.test.tsx`, soporte en `src/test/setup.ts` y `src/test/helpers.tsx`.

### Dependencias
No se añadió ninguna. No se ejecutó `pnpm install`.

## Decisiones

### Canonicalización JCS (RFC 8785)
- Claves ordenadas con comparación de cadenas JS (`<`/`>`), que compara por unidades de código UTF-16, no por punto de código. Probado con el ejemplo del RFC §3.2.3 y con un caso U+E000 frente a un emoji.
- Números: `String(n)` de ECMAScript (exactamente `Number::toString`), con `-0` → `0`. `NaN`/`±Infinity` se rechazan.
- Cadenas: tras comprobar que están bien formadas (sin surrogates sueltos, también en claves) se serializan con `JSON.stringify`, que produce el escape mínimo del RFC (`\b \t \n \f \r \" \\`, resto de controles en `\u00xx` minúscula, el resto literal).
- Se rechazan con `CanonicalizationError` (`code`: `UNSUPPORTED_TYPE`, `NON_FINITE_NUMBER`, `LONE_SURROGATE`, `CYCLE`, `MAX_DEPTH`): `undefined` (también como miembro de objeto y huecos de arrays), funciones, `bigint`, `symbol`, claves `symbol`, objetos no planos (Date, Map, instancias de clase), ciclos y profundidad > 256. Las referencias compartidas que no son ciclos se aceptan. Objetos con prototipo `null` y la clave `__proto__` (de `JSON.parse`) funcionan.
- Los vectores de prueba son los del propio RFC: ejemplo §3.2.2 (entrada y salida textual), ordenación §3.2.3 y la tabla del Apéndice B (24 doubles IEEE 754 + 3 rechazos). Nota: el valor del RFC para `0xbecbf647612f3696` que usé es `-0.0000033333333333333333`, que es lo que produce V8; una primera versión de la prueba tenía mal una cifra (`...335`) y se corrigió a lo que da el motor, que es la referencia de ECMAScript.

### Formato de firma y verificación
- ECDSA P-256 / SHA-256 sobre los bytes UTF-8 del JSON canónico, firma IEEE P1363 (`r‖s`, 64 bytes) en base64url, tal como pide el contrato. Web Crypto produce y espera P1363 de forma nativa; Node debe usar `dsaEncoding: 'ieee-p1363'` (lo hace el generador).
- `verifyCanonicalSignature` devuelve `false` (nunca `true`) para base64url inválido, longitud ≠ 64 o firma incorrecta (incluida una firma DER). Lanza `CanonicalizationError` si el documento no es canonicalizable y `VerificationError` si la clave es inválida.
- `importPublicKeyJwk`: `extractable: false`, `usages: ['verify']`, reconstruye una JWK limpia (`kty,crv,x,y`; `kid` y extras no pasan a Web Crypto), rechaza con `PRIVATE_KEY_REJECTED` cualquier JWK con `d` (y `p,q,dp,dq,qi,oth,k`), curva distinta, coordenadas que no miden 32 bytes y puntos fuera de la curva.
- base64url estricto: sin `=`, sin espacios, solo alfabeto URL-safe, longitud imposible (`%4==1`) y bits sobrantes no nulos rechazados (una codificación por valor).
- `computeKid(jwk)`: SHA-256 base64url de la SPKI DER; coincide con el `kid` del contrato (verificado contra `node:crypto`).
- Imports internos con extensión `.ts` + `rewriteRelativeImportExtensions` en `tsconfig.build.json`: `dist/` sale con `.js`, y el script de vectores se ejecuta directamente con `node scripts/generate-p13-vectors.ts` (Node 24 elimina tipos) importando `../src/canonicalize.ts`, sin depender de `dist` ni de `tsx`.

### Generador de vectores
La clave privada solo existe como `KeyObject` en memoria durante la ejecución; solo se escriben JWK pública, documentos, canónico, SHA-256 y firmas. El generador se ejecuta contra `src/`, de modo que los vectores usan la misma `canonicalize` que se prueba.

### Cliente API y CSRF (`src/lib/api.ts`)
- Rutas relativas (`/api/v1/...`, `API_PREFIX` de shared), `credentials: 'same-origin'`, `Accept: application/json`.
- Token CSRF solo en memoria (variable de cierre del cliente). Se obtiene de `GET /auth/csrf` la primera vez que hace falta (peticiones simultáneas comparten una sola consulta), se envía en `X-CSRF-Token` (constante `CSRF_HEADER` de shared) en todo método no seguro, incluido el login anónimo. El login sustituye el token por el `csrfToken` de su respuesta. Tras el logout se descarta y se pide uno nuevo inmediatamente.
- Ante `403 CSRF_INVALID` se descarta el token, se pide otro y se reintenta una sola vez; un segundo fallo se propaga.
- Todas las respuestas 2xx se validan con los esquemas Zod de `@alertasegura/shared` (`INVALID_RESPONSE` si no cumplen); los errores se interpretan con `ApiErrorSchema` a un `ApiError` (`status`, `code`, `message`, `issues`, `retryAfterSeconds` desde `Retry-After`, en segundos o fecha HTTP). Cuerpos de error ajenos al contrato → `INTERNAL_ERROR` (o `RATE_LIMITED` si es 429); fallo de red → `NETWORK_ERROR`.
- Un `401 UNAUTHENTICATED` en cualquier petición protegida notifica a `AuthProvider`, que pasa a anónimo (el panel redirige a `/login`).
- Nada en `localStorage`/`sessionStorage`, sin `dangerouslySetInnerHTML`, sin variables `VITE_*`.

### Sesión y rutas
`AuthProvider` consulta `/auth/me` al cargar (estados `loading` / `anonymous` / `authenticated`). `ProtectedRoute` redirige a `/login` con `state.from` (validado como ruta interna al volver, para evitar redirecciones abiertas) y, con la prop `permission`, muestra «Acceso no permitido» sin llamar a la API. Las comprobaciones de permisos del frontend son solo de interfaz y el pie de página lo indica. Rutas: `/`, `/login`, `/panel`, `/panel/usuarios` (`users:read`), `/panel/borradores` (`drafts:read-own`), `/panel/auditoria` (`audit:read`), `/laboratorio/criptografia`, `*` (404).

### Login
Etiquetas asociadas, `autocomplete="username"` / `current-password`, validación con `LoginRequestSchema` de shared antes de enviar, mensaje único «Correo o contraseña incorrectos.» para cualquier 401, mensaje de 429 con el tiempo de `Retry-After` («en 2 minutos» / «en 30 segundos»), contraseña vaciada tras un fallo, botón deshabilitado y `aria-busy` mientras envía, errores en región `role="alert"`.

### Laboratorio criptográfico
Importa `tests/fixtures/crypto/p13-vectors.json` en tiempo de compilación y verifica en el navegador, con `@alertasegura/verification`, cada vector (resumen «N de N verificados correctamente»). Permite editar el JSON o la firma y muestra forma canónica, SHA-256 y veredicto; hay botones para alterar un campo, añadir una clave, invertir un bit de la firma y restaurar. Solo usa la clave pública.

## Comandos y salida real

```
> pnpm --filter @alertasegura/verification vectors
Vectores P13 escritos en ...\tests\fixtures\crypto\p13-vectors.json
kid: hguE1zhX04U6lFELNMJYNO7W7cK2SPVo8OjUjIUXYrw
  alert-basic: sha256=6679e3c2ebdaa682f12a0dfa65ea52c7527ad8ff561e5c297809c7273e280d53 sig=JZxX1gXBZ7SsNQAJ…
  alert-unicode: sha256=6bfbb0f2f50a0d41d45b53aeb7011776402b739d17573e421a8e4bb7ba2a1aa6 sig=HEvNDsguf-yY1u2-…
  numbers: sha256=cb7f5e9b5c2856b1ae980162f8b952ddba857cef97732decf5b24f98a325d01c sig=ETOErsrmwlBv_m29…
  nested: sha256=2b5f921e45e83be7678de3c950265d8497fac535ff954c38ce9c55db69f5b448 sig=88HYAUyNMV8ZD-cy…
  rfc8785-sample: sha256=2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb sig=up-TtqexDRb5h8Gf…

> pnpm --filter @alertasegura/verification typecheck
$ tsc -p tsconfig.json                      (sin errores)

> pnpm --filter @alertasegura/verification build
$ node -e "...rmSync('dist'...)" && tsc -p tsconfig.build.json   (sin errores)

> pnpm --filter @alertasegura/verification test
 Test Files  3 passed (3)
      Tests  112 passed (112)

> pnpm --filter @alertasegura/web typecheck
$ tsc -b                                    (sin errores)

> pnpm --filter @alertasegura/web lint
$ oxlint                                    (sin avisos ni errores)

> pnpm --filter @alertasegura/web test
 Test Files  5 passed (5)
      Tests  35 passed (35)

> pnpm --filter @alertasegura/web build
$ tsc -b && vite build
✓ 151 modules transformed.
dist/index.html                   0.56 kB │ gzip:   0.33 kB
dist/assets/index-nXy8PRrd.css    5.22 kB │ gzip:   1.84 kB
dist/assets/index-CIIoaMgL.js   384.88 kB │ gzip: 119.07 kB
✓ built in 881ms
```

Desglose de las pruebas de `verification` (112): canonicalize 56 (ejemplo RFC §3.2.2, ordenación §3.2.3, 24 números del Apéndice B + 3 rechazos, escapes, 17 rechazos tipados, ciclos, profundidad), base64url 10 (vectores RFC 4648 §10, alfabeto URL-safe, ida y vuelta con bytes aleatorios de 0 a 130 de longitud contra `Buffer`, 7 entradas inválidas), `P13` 46.

Pruebas `describe('P13 …')` (`test/p13-interop.test.ts`):
- «P13 vectores generados en Node verificados con Web Crypto»: material solo público, `kid` = SHA-256 de la SPKI DER (Node y Web Crypto); y por cada uno de los 5 vectores: forma canónica reproducida, SHA-256 reproducido, firma de 64 bytes verificada con `verifyCanonicalSignature` y verificada directamente con `crypto.subtle`.
- «P13 rechazo de contenido alterado»: campo cambiado, número alterado, clave añadida, clave eliminada, cambio de tipo, **los 512 bits de la firma invertidos de uno en uno**, firma de otro documento, otra clave pública, firmas de longitud incorrecta/base64url inválido/firma DER (todas `false`), payload no canonicalizable (lanza).
- «P13 importación de claves públicas»: no extraíble y solo `verify`, JWK con `d` rechazada, 7 JWK inválidas.
- «P13 interoperabilidad bidireccional Node <-> Web Crypto»: firma en Node con `ieee-p1363` → verifica `crypto.subtle`; firma con `crypto.subtle` → verifica `node:crypto` (y un documento alterado se rechaza en Node); `kid` calculado con Web Crypto = el de Node.

Pruebas de `web` (35): `api.test.ts` 12 (envío de `X-CSRF-Token`, reutilización del token, reintento único tras `CSRF_INVALID`, tope de un reintento, login/logout con token de sesión y token nuevo, sin almacenamiento web, `Retry-After`, errores fuera de contrato, esquema de shared, red, 401); `LoginPage.test.tsx` 7 (etiquetas/autocomplete, éxito, 401, 429 en minutos y segundos, botón deshabilitado mientras envía, validación de cliente); `ProtectedRoute.test.tsx` 9 (redirección a `/login` con 401 en `/panel` y subruta, estado de carga, panel con sesión, emisor sin enlaces de admin, «Acceso no permitido» sin llamada, lista de usuarios, logout, sesión caducada); `DraftsPage.test.tsx` 2; `CryptoLabPage.test.tsx` 5 (los vectores verifican en jsdom con Web Crypto, alterar campo/bit/clave invierte el veredicto y restaurar lo recupera).

Comprobación manual del proxy: con `vite` en marcha, `GET http://127.0.0.1:5173/` → 200, `/laboratorio/criptografia` → 200 (SPA), `/api/v1/health` → 502 `ECONNREFUSED` porque la API no estaba levantada; es decir, el proxy reenvía a `localhost:3000` como se espera.

## Bloqueos / pendientes
- **Sin integración real con la API.** FORGE no tenía el servidor levantado durante mi trabajo; todo el flujo de login/CSRF/listados se probó con `fetch` simulado según `api-contract.md`. Pendiente de ATLAS: prueba con la API real (login con sesión y cookie `as_session`/`as_csrf`, `Retry-After` real en 429, `CSRF_INVALID` real, `Origin` = `http://localhost:5173`).
- **Cambios de contrato solicitados: ninguno.** Dos observaciones: (1) `CSRF_HEADER` está en minúsculas (`x-csrf-token`); las cabeceras HTTP no distinguen mayúsculas, así que funciona, pero el encargo habla de `X-CSRF-Token`; (2) el cliente lee `Retry-After`: la API debe enviarlo en los 429 (el contrato ya lo indica).
- No implementado por no estar en el encargo: formulario para `POST /admin/issuers` (alta de emisores), publicación de borradores, módulo de alertas ciudadanas, PWA/service worker. La consulta ciudadana de `/` es solo un aviso informativo.
- Sin cabecera CSP: una `<meta>` CSP rompería el HMR de desarrollo; debería fijarla el servidor/proxy de producción (`script-src 'self'`, sin `unsafe-inline`; el build de Vite no emite scripts inline).
- El frontend importa `@alertasegura/verification` y `@alertasegura/shared` desde su `dist`: hay que ejecutar `pnpm build:packages` antes de `dev`/`build`/`test` de `apps/web` en un clon limpio (el script `dev` de la raíz ya lo hace). El `dist` de `verification` está reconstruido con el código actual.
- Los archivos de pruebas contienen algunos caracteres Unicode invisibles escritos literalmente (p. ej. U+E000, U+2028) en `packages/verification/test/canonicalize.test.ts` en lugar de secuencias `\u`; son válidos y las pruebas pasan, pero un revisor podría preferir las secuencias explícitas.
- `apps/frontend/` no se tocó. La carpeta `apps/web/dist` anterior (ignorada por git) fue sustituida por el nuevo build.

## Correcciones de revisión ATLAS

Problema reportado: con `pnpm test` desde la raíz (Jest de api y Vitest en paralelo) fallaban 3 pruebas de `apps/web` por tiempo agotado (inestabilidad, no fallo funcional). Cambios, solo en `apps/web`:

1. `vite.config.ts` › `test`: `testTimeout: 20000` y `hookTimeout: 20000`.
2. `src/test/setup.ts`: `configure({ asyncUtilTimeout: 5000 })` de Testing Library (solo amplía la espera máxima de `findBy`/`waitFor`; no añade pausas fijas).
3. Pruebas más rápidas sin perder lo que verifican: todos los `userEvent.setup()` pasan a `userEvent.setup({ delay: null })` (sin pausas entre pulsaciones; se sigue tecleando en los campos de login y título) y en `DraftsPage.test.tsx` el mensaje largo se introduce con `user.click` + `user.paste` (el tecleo carácter a carácter no aportaba nada a la verificación del POST con `X-CSRF-Token`).

Verificación real:

```
> pnpm --filter @alertasegura/web typecheck     $ tsc -b     (sin errores)
> pnpm --filter @alertasegura/web lint          $ oxlint     (sin avisos ni errores)
> pnpm --filter @alertasegura/web test          Test Files 5 passed (5) · Tests 35 passed (35) · Duration 7.14s

> pnpm test   (raíz, api + web + verification en paralelo) — ejecución 1: exit=0
packages/verification test:  Tests  112 passed (112)
apps/web test:               Tests   35 passed (35)   Duration 12.93s
apps/api test:               Tests:  62 passed, 62 total   Time: 7.101 s

> pnpm test   (raíz) — ejecución 2: exit=0
packages/verification test:  Tests  112 passed (112)
apps/api test:               Tests:  62 passed, 62 total   Time: 6.331 s
apps/web test:               Tests   35 passed (35)   Duration 11.76s
```

Antes la suite de web tardaba 10 a 45 s según la carga; ahora ronda 7 s sola y 12 s en paralelo con las demás.
