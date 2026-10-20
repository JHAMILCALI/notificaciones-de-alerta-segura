# Semana 1 — Resumen de lo realizado y cumplido

**Proyecto:** AlertaSegura · Seguridad de la Información (4 semanas)
**Autor:** Jhamil Calixto Mamani Quea · **Rama:** `feat/semana-1` · **Cierre:** 2026-10-20
**Resultado:** **GATE G1 APROBADO** (P01, P02a, P02b, P09 y P13)

Este documento reúne en un solo lugar todo lo hecho en la semana 1: qué se construyó, cómo se protegió, qué pruebas
se aprobaron, qué evidencias hay y qué queda pendiente. El detalle de cada prueba está en el
[reporte de cumplimiento](evidence/semana1-cumplimiento.md).

---

## 1. Objetivo de la semana 1

Según la propuesta oficial (`AlertaSegura_Propuesta_Definitiva_Seguridad_4_Semanas.pdf`, sección 11), la semana 1 debía
dejar lista la **base segura** del sistema:

- Monorepo funcionando con API, PWA y base de datos.
- **Identidad y acceso:** login seguro, sesiones, roles, permisos y propiedad.
- Protección **CSRF** y **rate limiting**.
- **Auditoría** básica e inalterable.
- **Canonicalización JCS** y compatibilidad de firmas entre Node.js y el navegador (Web Crypto).
- Documentación de arquitectura, modelo SQL y modelo de amenazas T1–T11.
- Aprobar el **GATE G1**: P01, P02a, P02b, P09 y P13.

Quedaron fuera a propósito, porque son de las semanas 2 a 4: la firma real de alertas, la publicación, la cancelación,
las claves, el verificador PWA final y el modo sin conexión.

---

## 2. Resumen en una tabla

| Área | Qué se logró | Estado |
| --- | --- | --- |
| Monorepo | pnpm workspaces con 3 apps y 3 paquetes; build, typecheck y lint en verde | ✅ |
| Base de datos | PostgreSQL 17 en Docker, Prisma 7, 2 migraciones, seed de 4 usuarios | ✅ |
| API | NestJS 11 con 12 endpoints bajo `/api/v1` | ✅ |
| Autenticación | Argon2id, sesiones en servidor, cookies HttpOnly + SameSite=Strict | ✅ |
| Autorización | 3 roles, permisos por ruta (RBAC) y control de propiedad | ✅ |
| CSRF | Double-submit firmado con HMAC + validación de `Origin` | ✅ |
| Rate limiting | Por IP, por cuenta, por usuario y global; 429 con `Retry-After` | ✅ |
| Auditoría | Tabla append-only protegida por triggers | ✅ |
| Criptografía | JCS (RFC 8785) + ECDSA P-256/SHA-256 verificable en Node y Web Crypto | ✅ |
| PWA | React 19 + Vite: inicio, login, panel, borradores y laboratorio criptográfico | ✅ |
| Pruebas | 209 unitarias, 77 e2e, 39 de caja negra, 46 P13, 17 en Chrome real | ✅ |
| Documentación | Arquitectura, BD, amenazas T1–T11, contrato API, guías de inicio | ✅ |
| GATE G1 | P01, P02a, P02b, P09 y P13 | ✅ **APROBADO** |

---

## 3. Estructura del proyecto

```text
alertasegura/
├── apps/
│   ├── api/            API NestJS: auth, users, drafts, audit, health
│   ├── web/            PWA React + Vite (único frontend; apps/frontend no se usa)
│   └── signer/         firmante aislado (se implementa en la semana 2)
├── packages/
│   ├── shared/         contratos Zod, roles y permisos (ESM + CommonJS)
│   ├── database/       esquema Prisma, migraciones, seed y hashing Argon2id
│   └── verification/   JCS RFC 8785 y verificación ECDSA con Web Crypto
├── tools/trust-cli/    administración de claves (semana 2)
├── infra/compose.yml   PostgreSQL 17 en Docker
├── tests/
│   ├── fixtures/crypto/p13-vectors.json
│   └── security/       aceptación G1, integración, Chrome real y limpieza
└── docs/               arquitectura, BD, amenazas, coordinación y evidencias
```

**Tecnologías:** Node 24, pnpm 12, TypeScript, NestJS 11, React 19, Vite 8, PostgreSQL 17, Prisma 7, Zod,
Argon2id (`@node-rs/argon2`), Web Crypto, Jest 30, Vitest y Playwright (con el Chrome instalado).

---

## 4. Qué se construyó

### 4.1 Base de datos (`packages/database`)

| Tabla | Para qué sirve |
| --- | --- |
| `User` | Usuarios con correo único, nombre, rol, estado y hash Argon2id de la contraseña |
| `Session` | Sesiones del servidor; solo se guarda el **SHA-256** del token, nunca el token |
| `Draft` | Borradores de alerta (título, cuerpo, severidad) con su dueño |
| `AuditLog` | Registro de eventos de seguridad; **no se puede modificar ni borrar** |

- **Migraciones:** `20261019211004_init` y `20261019213000_audit_append_only_error_code`.
- **Triggers:** bloquean `UPDATE`, `DELETE` y `TRUNCATE` sobre `AuditLog`.
- **Seed:** crea admin, auditor y dos emisores con las contraseñas del `.env` (mínimo 12 caracteres). Es idempotente:
  si el usuario ya existe, no lo modifica.

### 4.2 API (`apps/api`)

| Endpoint | Quién puede | Qué hace |
| --- | --- | --- |
| `GET /health` | público | Estado de la API y de la base de datos |
| `GET /auth/csrf` | público | Entrega el token CSRF |
| `POST /auth/login` | público + CSRF | Inicia sesión |
| `POST /auth/logout` | sesión + CSRF | Cierra y revoca la sesión |
| `GET /auth/me` | sesión | Datos del usuario, rol y permisos |
| `GET /admin/users` | ADMIN | Lista de usuarios |
| `POST /admin/issuers` | ADMIN + CSRF | Da de alta un emisor (queda auditado) |
| `POST /drafts` | ISSUER + CSRF | Crea un borrador |
| `GET /drafts` | ISSUER | Lista **solo sus** borradores |
| `GET /drafts/:id` | ISSUER dueño | Ver un borrador propio |
| `POST /drafts/:id/publish` | ISSUER dueño + CSRF | Autoriza y audita; responde **501** porque la firma es de la semana 2 |
| `GET /audit` | ADMIN, AUDITOR | Consulta de la auditoría |

**Orden de los controles en cada ruta protegida:**

```text
rate limit (429) → autenticación (401) → CSRF (403) → validación Zod (400) → rol (403) → propiedad (403/404)
```

### 4.3 PWA (`apps/web`)

| Ruta | Acceso | Contenido |
| --- | --- | --- |
| `/` | público | Inicio / consulta ciudadana |
| `/login` | público | Formulario de inicio de sesión |
| `/panel` | con sesión | Nombre, rol, permisos y secciones disponibles |
| `/panel/borradores` | emisor | Crear y listar sus borradores |
| `/laboratorio/criptografia` | público | Verifica firmas de prueba con Web Crypto y muestra cómo se rechazan las alteradas |

- **Token CSRF:** se guarda solo en memoria. Nada queda en `localStorage` ni en `sessionStorage`.
- **Comunicación con la API:** todo `/api` pasa por el proxy de Vite hacia la API.
- **Pantallas pequeñas:** se ve bien a 360 px de ancho, sin scroll horizontal.

### 4.4 Criptografía (`packages/verification`)

- **Canonicalización JCS (RFC 8785):** el mismo JSON produce siempre los mismos bytes.
- **Firma:** ECDSA P-256 con SHA-256. La firma va en formato P1363 (64 bytes) codificada en base64url, y la clave
  pública en JWK.
- **Identificador de clave (`kid`):** es el SHA-256 de la clave pública (SPKI).
- **Vectores P13:** se generaron con una clave **efímera** que se descartó. En el repositorio no hay ninguna clave privada.

---

## 5. Controles de seguridad implementados

| Control | Cómo se hizo | Amenaza que cubre |
| --- | --- | --- |
| Contraseñas | Argon2id (m=19456, t=2, p=1). Las cuentas inexistentes también calculan un hash, para no revelar por el tiempo de respuesta qué cuentas existen | T1, T8 |
| Mensaje de error genérico | El mismo 401 para contraseña errónea y para cuenta inexistente | T1 |
| Sesiones | Token aleatorio de 32 bytes, guardado solo como hash. Caduca tras 30 min sin actividad u 8 h en total; se rota al iniciar sesión y se revoca al salir | T1 |
| Cookies | `HttpOnly`, `SameSite=Strict`, `Path=/`. Con HTTPS, también `Secure` y prefijo `__Host-` | T1 |
| CSRF | El token es un nonce firmado con HMAC y ligado a la sesión, más un encabezado `X-CSRF-Token`. Se rechaza cualquier `Origin` ajeno | T1 |
| RBAC | ADMIN gestiona y **no publica**; ISSUER crea y publica; AUDITOR solo lee la auditoría | T1, T10 |
| Propiedad | Un emisor no puede ver ni publicar borradores de otro | T10 |
| Rate limiting | Login: 10 por IP por minuto y 5 fallos por cuenta cada 15 min. 120 peticiones por usuario y 300 globales por minuto | T8 |
| Validación | Esquemas Zod estrictos: rechazan campos de más (protección contra *mass assignment*) | T1, T2 |
| Auditoría | Registra login, logout, altas, denegaciones, autorizaciones y 429. Es append-only | T7 |
| Encabezados HTTP | `helmet`, cuerpo de petición de 100 kB como máximo y sin CORS abierto | General |
| Secretos | `.env` fuera de Git. La API no arranca si `CSRF_SECRET` es el valor de ejemplo | General |

---

## 6. GATE G1 — Pruebas oficiales

| Prueba | Qué exige la propuesta | Resultado | Evidencia |
| --- | --- | --- | --- |
| **P01** | Login correcto, roles, sesión protegida y alta de emisores auditada | e2e 31/31 · caja negra 19/19 | [`P01.json`](evidence/g1/P01.json) |
| **P02a** | Un anónimo intenta publicar → 401 | e2e 6/6 · caja negra 4/4 | [`P02a.json`](evidence/g1/P02a.json) |
| **P02b** | Un autenticado sin permiso intenta publicar → 403 | e2e 10/10 · caja negra 10/10 | [`P02b.json`](evidence/g1/P02b.json) |
| **P09** | Exceso de intentos de login → 429 | e2e 15/15 · caja negra 6/6 | [`P09.json`](evidence/g1/P09.json) |
| **P13** | Firma en Node.js verificada en Web Crypto, con vectores válidos y alterados | Vitest 46/46 | [`P13-vitest.json`](evidence/g1/P13-vitest.json) |

**Qué se observó en cada prueba:**

- **P01:** la contraseña errónea y la cuenta inexistente dan el mismo 401. La cookie llega con
  `HttpOnly; SameSite=Strict`. Ninguna respuesta incluye `passwordHash`. Las altas de emisores quedan auditadas, y tras el
  logout la cookie anterior ya no sirve.
- **P02a:** sin sesión, publicar responde 401 `UNAUTHENTICATED`, aunque se envíe un token CSRF válido.
- **P02b:** el AUDITOR, el ADMIN y el emisor B reciben 403. Al emisor A dueño del borrador se le rechaza con 403
  `CSRF_INVALID` si no envía el token CSRF, si envía el de otra sesión o si la petición viene de un `Origin` ajeno. Solo el
  dueño, con todo correcto, obtiene el 501 esperado.
- **P09:** con la misma cuenta, `401 ×5 → 429`. Con distintas cuentas desde la misma IP, el 429 llega en el intento 11.
  Un usuario recibe 429 en su petición 121, mientras otro usuario sigue recibiendo 200.
- **P13:** 5 vectores verifican en ambos sentidos. Se rechazan todos los alterados: un campo cambiado, una clave añadida,
  cualquiera de los 512 bits de la firma invertido, una firma en DER, otra clave o una JWK con parte privada.

### Totales de pruebas

| Suite | Resultado |
| --- | --- |
| Unitarias (api 62 · web 35 · verification 112) | **209/209** |
| e2e de la API contra PostgreSQL real | **77/77** |
| Aceptación G1 de caja negra | **39/39** |
| P13 (Vitest) | **46/46** |
| Integración PWA ⇄ API por el proxy de Vite | ✅ |
| Recorrido en Google Chrome real (complementaria) | **17/17** |
| `pnpm build`, `pnpm typecheck`, `pnpm lint` | ✅ sin errores |

> Las 17 comprobaciones en Chrome son **evidencia complementaria**: no sustituyen a las pruebas G1 del backend.

---

## 7. Evidencias

Todo está en [`docs/evidence/`](evidence/):

| Carpeta / archivo | Contenido |
| --- | --- |
| [`evidence/semana1-cumplimiento.md`](evidence/semana1-cumplimiento.md) | Reporte formal de cumplimiento, prueba por prueba |
| `evidence/g1/P01.json` … `P09.json` | Resultados de la caja negra con peticiones y respuestas reales |
| `evidence/g1/P13-vitest.json`, `e2e-jest.json` | Resultados de Vitest y Jest |
| `evidence/g1/integracion-web-api.json` | Prueba de la PWA hablando con la API |
| `evidence/g1/logs/` | 14 registros: base de datos, build, typecheck, pruebas, lint, Chrome y limpieza |
| `evidence/g1/navegador/` | 12 capturas en Chrome real y `resultado.json` |

**Capturas en el navegador:**

| # | Captura | Qué demuestra |
| --- | --- | --- |
| 01 | [inicio](evidence/g1/navegador/01-inicio.png) | Página pública de inicio |
| 02 | [panel sin sesión](evidence/g1/navegador/02-panel-sin-sesion-redirige.png) | `/panel` sin sesión redirige al login |
| 03 | [error genérico](evidence/g1/navegador/03-login-error-generico.png) | Contraseña errónea: mensaje genérico |
| 04 | [panel emisor](evidence/g1/navegador/04-panel-emisor.png) | Login correcto con rol y permisos |
| 05 | [borrador creado](evidence/g1/navegador/05-borrador-creado.png) | Borrador creado con token CSRF |
| 06 | [vectores válidos](evidence/g1/navegador/06-lab-vectores-validos.png) | P13 en el navegador: 5/5 válidos |
| 07 | [campo alterado](evidence/g1/navegador/07-lab-campo-alterado.png) | Campo alterado → firma inválida |
| 08 | [clave añadida](evidence/g1/navegador/08-lab-clave-anadida.png) | Clave añadida → firma inválida |
| 09 | [bit de firma](evidence/g1/navegador/09-lab-bit-firma.png) | Bit de la firma alterado → inválida |
| 10 | [laboratorio móvil](evidence/g1/navegador/10-lab-movil-360.png) | Laboratorio a 360 px |
| 11 | [panel móvil](evidence/g1/navegador/11-panel-movil-360.png) | Panel a 360 px |
| 12 | [logout](evidence/g1/navegador/12-logout.png) | Cierre de sesión |

---

## 8. Modelo de amenazas T1–T11

La matriz de [`threat-model/README.md`](threat-model/README.md) sigue la **sección 09 oficial** de la propuesta.

| ID | Amenaza | Riesgo | Pruebas | Estado tras la semana 1 |
| --- | --- | --- | --- | --- |
| T1 | Publicación anónima o sin rol | ALTO | P01, P02a–b | ✅ Mitigado |
| T2 | Modificación de la alerta en la API o la BD | ALTO | P03, P07, P11 | 🟡 Parcial (P13 listo) |
| T3 | Firma con una clave robada | ALTO | P04, P14 | ⏳ Semana 2–3 |
| T4 | Alerta caducada presentada como vigente | MEDIO | P05 | ⏳ Pendiente |
| T5 | Cancelación falsa | ALTO | P06 | ⏳ Semana 2 |
| T6 | Escritura sobre una alerta publicada | ALTO | P07 | ⏳ Semana 2 |
| T7 | Auditoría modificada | MEDIO | P08, P08b | 🟡 Parcial (append-only listo) |
| T8 | Fuerza bruta o abuso | MEDIO | P09 | ✅ Mitigado |
| T9 | Datos obsoletos en la PWA | MEDIO | P10 | ⏳ Pendiente |
| T10 | Un emisor afecta la alerta de otro | ALTO | P02c | 🟡 Parcial (propiedad en borradores) |
| T11 | Supresión de una cancelación | ALTO | P06b | ⏳ Pendiente |

Las 7 amenazas ALTAS tienen control y prueba asignados, como exige el objetivo OE1.

---

## 9. Problemas encontrados y cómo se resolvieron

| Problema | Solución |
| --- | --- |
| La primera matriz T1–T11 no coincidía con la propuesta oficial | Se reescribió según la sección 09 |
| 351 errores de ESLint en la API | Se corrigieron sin desactivar reglas |
| La API aceptaba el `CSRF_SECRET` de ejemplo | Ahora se niega a arrancar con él |
| 3 pruebas de la web fallaban a veces por tiempo | Se ajustaron los tiempos y quedaron estables |
| El script de aceptación pisaba la cabecera CSRF (falso fallo) | Se corrigió el script |
| La integración fallaba con 429 justo después de P09 | Ahora respeta `Retry-After` |
| El laboratorio se desbordaba 8 px a 360 px | Se corrigió el CSS de la lista de datos |
| Al clonar desde cero, faltaba compilar `@alertasegura/database` | `pnpm build:packages` ahora lo incluye |
| Las pruebas dejaban borradores en la BD de desarrollo | Se implementó una limpieza específica y segura (`pnpm test:cleanup`) |
| El puerto 5432 estaba ocupado por un PostgreSQL de Windows | Se usa el 5433 en el `.env` local |

---

## 10. Comprobaciones de seguridad adicionales

| Comprobación | Resultado |
| --- | --- |
| Claves privadas (PEM o JWK con `d`) en el repositorio | Ninguna |
| `.env`, cliente Prisma generado o `dist/` en Git | No, están ignorados |
| Contraseñas o secretos reales en archivos versionados o evidencias | Ninguno |
| Material privado en el bundle de la PWA | Ninguno |
| Revisión de código de sesiones, CSRF, autenticación, propiedad y auditoría | Sin defectos encontrados |

---

## 11. Documentación generada

| Documento | Contenido |
| --- | --- |
| [`README.md`](../README.md) | Cómo levantar todo en local e iniciar sesión |
| [`guia-inicio-local.md`](guia-inicio-local.md) | Paso a paso detallado, en orden, con comprobaciones |
| [`architecture/README.md`](architecture/README.md) | Arquitectura y decisiones técnicas |
| [`database/README.md`](database/README.md) | Modelo SQL, invariantes y migraciones |
| [`threat-model/README.md`](threat-model/README.md) | Amenazas T1–T11, actores y riesgos residuales |
| [`coordination/api-contract.md`](coordination/api-contract.md) | Contrato de la API, límites y orden de los controles |
| [`evidence/semana1-cumplimiento.md`](evidence/semana1-cumplimiento.md) | Reporte formal del GATE G1 |

---

## 12. Commits de la semana 1 (rama `feat/semana-1`)

| Commit | Descripción |
| --- | --- |
| `f885ea7` | build: scripts del workspace y dependencias |
| `1792f45` | feat(shared): contratos Zod, roles y permisos |
| `18afa0f` | feat(database): esquema Prisma, migraciones y seed |
| `d25b42a` | feat(api): autenticación, sesiones, CSRF, RBAC, rate limiting y auditoría |
| `8ea877c` | feat(verification): JCS RFC 8785 y ECDSA P-256 con Web Crypto |
| `4057017` | feat(web): login, sesión, panel y laboratorio criptográfico |
| `38ff76e` | docs: arquitectura, modelo SQL, amenazas y coordinación |
| `bf25837` | test(security): aceptación del GATE G1 y evidencias |
| `c2f75dd` | fix(web): desbordamiento del laboratorio a 360 px |
| `5b3dfb0` | test(security): recorrido en Chrome real con capturas |
| `a675d17` | docs(threat-model): matriz T1–T11 según la sección 09 oficial |
| `3f6d7f2` | test(security): limpieza específica de borradores de prueba |
| `d2261fa` | docs(evidence): validación final del G1 y reporte de cumplimiento |
| `4d3ecf0` | build: compilar también `database` en `build:packages` |
| `76659b8` | docs(readme): levantar en local desde cero e iniciar sesión |
| `7cb3fc9` | docs: guía de inicio local paso a paso |

En total: 224 archivos cambiados y unas 13 650 líneas añadidas. Todo está solo en local, sin push.

---

## 13. Lo que queda pendiente

### Diferencias con la propuesta oficial (requieren decisión)

| # | La propuesta dice | Se implementó | Impacto |
| --- | --- | --- | --- |
| D-1 | Altas de emisores mediante un script del responsable de laboratorio (§03) | Endpoint `POST /admin/issuers` del ADMIN | Afecta a P01 y T1 |
| D-2 | Actores: administrador, emisores A/B y ciudadano | Rol adicional **AUDITOR** | Rol no previsto |
| D-3 | Rutas `/admin` y `/alertas` | `/panel` y `/` | Solo nombres |
| D-4 | Borrador con `tipo`, `zona`, `severidad`, `mensaje`, `datos_temporales` | `title`, `body`, `severity` | Hay que ajustarlo antes de firmar en la semana 2 |
| D-5 | TLS de laboratorio (RNF01) | HTTP local | La cookie `Secure` no se probó sobre TLS real |
| D-6 | API Express | NestJS (que usa Express por debajo) | Justificada por el mandato del proyecto |

### Riesgos conocidos de la implementación

- El rate limiting vive en la memoria de un solo proceso: se reinicia al reiniciar la API.
- El límite por cuenta permite que un atacante bloquee temporalmente una cuenta conocida.
- La API usa el rol propietario de PostgreSQL. En la semana 2 se separará en un rol sin `UPDATE` ni `DELETE`.
- No hay purga automática de sesiones caducadas.
- Falta CSP en el servidor de desarrollo.

### Semana 2 (GATE G2)

Firmante aislado, publicación atómica firmada, evento `ALERTA_PUBLICADA`, rol SQL de solo inserción, cancelación firmada,
y las pruebas P02c, P03, P06, P07, P15 y P16.

---

## 14. Conclusión

La semana 1 está **completa**: se construyó la base segura del sistema y se aprobó el **GATE G1** con pruebas
reales contra el backend (P01, P02a, P02b, P09) y con la interoperabilidad criptográfica Node ⇄ Web Crypto (P13). Todo
está documentado y respaldado con evidencias reproducibles. Lo único pendiente son las decisiones D-1 a D-5 y el trabajo
propio de las semanas 2 a 4.
