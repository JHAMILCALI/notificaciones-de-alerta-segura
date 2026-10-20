# Modelo de amenazas

## Activos

| Activo | Por qué importa |
| --- | --- |
| Clave privada de firma | Quien la controla puede emitir alertas falsas que la PWA aceptará como auténticas |
| Cuentas de emisor y administrador | Permiten crear y publicar alertas o provisionar emisores |
| Sesiones activas | Equivalen a la cuenta mientras están vigentes |
| Integridad de las alertas | Una alerta alterada puede provocar daño real (pánico, evacuaciones innecesarias) |
| Registro de auditoría | Permite atribuir y reconstruir acciones críticas |
| Disponibilidad de la API | Durante una emergencia la publicación no puede bloquearse |

## Actores

Ciudadano anónimo · Emisor legítimo · Emisor malicioso o comprometido · Administrador · Auditor · Atacante externo en Internet · Atacante con acceso a la red local o al repositorio.

## Superficies de ataque

API REST pública (`/api/v1`), formulario de login, cookies de sesión, PWA en el navegador, base de datos, repositorio Git y variables de entorno, proceso firmante (semana 2).

## Matriz T1–T11

Riesgo = probabilidad × impacto (B/M/A). Estado en la semana 1: **Mitigado** (control implementado y probado), **Parcial** o **Pendiente** (semana indicada).

| ID | Amenaza (STRIDE) | Riesgo | Controles | Pruebas | Estado S1 |
| --- | --- | --- | --- | --- | --- |
| T1 | Suplantación de un emisor por fuerza bruta o *credential stuffing* (S) | **Alto** | Argon2id; límite de login por IP y por cuenta; mensaje genérico; hash señuelo para cuentas inexistentes; sin autorregistro | P01, P09 | Mitigado |
| T2 | Secuestro o fijación de sesión (S) | **Alto** | Token opaco de 32 bytes, solo su SHA-256 en BD; cookie HttpOnly + SameSite=Strict + Secure/`__Host-` bajo HTTPS; rotación en login; caducidad absoluta e inactividad; revocación en logout | P01 | Mitigado |
| T3 | CSRF: un sitio externo hace publicar al emisor (T/E) | **Alto** | SameSite=Strict; token *signed double-submit* ligado a la sesión en `X-CSRF-Token`; rechazo de `Origin` ajeno | P02b (sin token → 403), unitarias CSRF | Mitigado |
| T4 | Escalada vertical: anónimo o rol sin permiso publica (E) | **Alto** | Guard de autenticación global (401); RBAC en servidor con matriz única; ADMIN sin `alerts:publish` | P02a, P02b | Mitigado |
| T5 | Escalada horizontal / IDOR: un emisor usa borradores de otro (E) | **Alto** | Comprobación de propiedad en servidor tras RBAC | P02b (emisor no propietario → 403) | Mitigado |
| T6 | Alteración de una alerta en tránsito, en BD o en caché (T) | **Alto** | Firma ECDSA P-256/SHA-256 sobre JCS (RFC 8785); verificación en el cliente con Web Crypto; rechazo de cualquier cambio | P13 | Parcial: verificación lista; firma de alertas reales en S2 |
| T7 | Robo o uso indebido de la clave privada (S/T) | **Crítico** | Firmante aislado con usuario, red y secreto propios; la API y la PWA nunca leen la clave; `*.pem`/`*.key` ignorados; claves de laboratorio efímeras | Revisión: ninguna clave privada en el repositorio ni en el bundle | Pendiente S2 (aislamiento); verificado que no hay claves privadas |
| T8 | Denegación de servicio por abuso de endpoints (D) | Medio | Rate limiting global, por usuario y de login; límite de cuerpo JSON; longitud máxima de contraseña antes de Argon2id | P09 | Mitigado (una instancia) |
| T9 | Inyección y entrada malformada, *mass assignment* (T/E) | Medio | Prisma con consultas parametrizadas; Zod `strictObject` en todas las entradas; el rol lo fija el servidor | e2e de validación (400) | Mitigado |
| T10 | Repudio: no poder atribuir una acción crítica (R) | Medio | Auditoría de login, logout, denegaciones, CSRF, rate limiting, provisión y publicación; trigger que impide UPDATE/DELETE en `AuditLog` | e2e de auditoría y append-only | Mitigado |
| T11 | Fuga de información: trazas, secretos en Git, datos sensibles en logs (I) | Medio | Filtro global de errores sin detalles internos; `.env` ignorado; secretos generados localmente; nunca contraseñas ni tokens en auditoría; React sin `dangerouslySetInnerHTML` | Revisión de código y búsqueda de secretos | Mitigado |

## Amenazas altas → controles → pruebas

| Amenaza | Control verificable | Prueba G1 | Evidencia |
| --- | --- | --- | --- |
| T1 | 6.º login fallido para una cuenta → 429 con `Retry-After`; contraseña errónea → 401 genérico | P01, P09 | `docs/evidence/g1/` |
| T2 | Cookie `HttpOnly; SameSite=Strict`; tras logout la cookie anterior → 401 | P01 | `docs/evidence/g1/` |
| T3 | Publicar sin `X-CSRF-Token` → 403 `CSRF_INVALID` | P02b | `docs/evidence/g1/` |
| T4 | Anónimo → 401; AUDITOR/ADMIN → 403 | P02a, P02b | `docs/evidence/g1/` |
| T5 | Emisor B publica borrador de A → 403 | P02b | `docs/evidence/g1/` |
| T6 | Firma Node verificada en Web Crypto; contenido o firma alterados rechazados | P13 | `docs/evidence/g1/` |

## Riesgos pendientes

| ID | Riesgo | Plan |
| --- | --- | --- |
| R-01 | El firmante aislado no existe todavía (T7) | Semana 2 |
| R-02 | Sin HTTPS en desarrollo: `Secure` solo se activa con `COOKIE_SECURE=true` | Proxy TLS en despliegue; `COOKIE_SECURE=true` obligatorio en producción |
| R-03 | El rate limiting vive en memoria: se reinicia con el proceso y no se comparte entre instancias | Almacén compartido (Redis o PostgreSQL) si se escala |
| R-04 | Sin MFA para cuentas de emisor | Evaluar TOTP/WebAuthn en semanas posteriores |
| R-05 | Sin política de rotación ni revocación de claves públicas en la PWA | `tools/trust-cli` y manifiestos (semana 2–3) |
