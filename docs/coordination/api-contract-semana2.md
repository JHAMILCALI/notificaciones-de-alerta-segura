# Contrato API — Semana 2 (cambios sobre la semana 1)

Complementa a [`api-contract.md`](api-contract.md): todo lo que no se menciona aquí sigue igual (sesión, CSRF, orden
de controles, rate limiting, contraseñas). **Fuente de verdad de los tipos:** `packages/shared/src`.

| Archivo de `shared` | Contenido |
| --- | --- |
| `constants/bolivia.ts` | Departamentos, tipos de alerta, niveles (AMARILLA/NARANJA/ROJA), zona horaria `America/La_Paz`, vigencia 1–72 h |
| `schemas/drafts.ts` | Borrador con los campos oficiales (D-4) |
| `schemas/documents.ts` | Documentos firmados ALERTA, EVENTO, ESTADO, MANIFIESTO y el sobre firmado |
| `schemas/signer.ts` | Protocolo API → firmante |
| `schemas/alerts.ts` | Respuestas de `/alerts` y `/trust/manifest` |

## Decisiones aplicadas

| # | Decisión |
| --- | --- |
| D-1 | Se retira `POST /admin/issuers` (pasa a 404) y el permiso `issuers:provision`. Los emisores los da de alta el comando de laboratorio `pnpm lab issuer:add`, que audita `ISSUER_PROVISIONED` con `metadata.actor = "lab-script"` y `actorId = null` |
| D-2 | AUDITOR se mantiene (solo `audit:read`) |
| D-3 | Las rutas de la PWA pasan a `/admin` y `/alertas`, con redirecciones desde `/panel` y `/` (tarea BAJA) |
| D-4 | El borrador usa `tipo`, `zona {departamento, municipio}`, `severidad` (AMARILLA/NARANJA/ROJA), `mensaje` y `vigenciaHoras`. Al publicar: `emitida_en = ahora` y `expira_en = ahora + vigenciaHoras`, en UTC con segundos |
| D-5 | TLS de laboratorio con `mkcert` (MEDIA, al final; si no hay margen, en la semana 3) |
| D-6 | Se mantiene NestJS (sobre Express) y se documenta |

## Roles y permisos

| Rol | Permisos |
| --- | --- |
| ADMIN | `users:read`, `audit:read` |
| ISSUER | `drafts:create`, `drafts:read-own`, `alerts:publish`, `alerts:cancel` |
| AUDITOR | `audit:read` |

## Endpoints nuevos o cambiados

| Método y ruta | Control | Cuerpo | Respuestas |
| --- | --- | --- | --- |
| `POST /drafts` | `drafts:create` + CSRF | `CreateDraftRequest` (campos nuevos) | 201 `DraftResponse` |
| `POST /drafts/:draftId/publish` | `alerts:publish` + propiedad + CSRF + cuota | — | **201 `AlertaResponse`** · 409 `CONFLICT` si ya está publicado · 503 `SIGNER_UNAVAILABLE` sin efectos · 429 si se excede la cuota |
| `POST /alerts/:alertaId/cancel` | `alerts:cancel` + propiedad (`emisor_id`) + CSRF | `{}` estricto | 201 `AlertaResponse` (con el evento y el estado CANCELADA) · 403 si es de otro emisor (`CANCEL_DENIED`, P02c) · 404 · 409 si ya está cancelada · 503 |
| `GET /alerts` | público | `?limit=` | 200 `AlertaListResponse` |
| `GET /alerts/:alertaId` | público | — | 200 `AlertaResponse` (estado fresco: se regenera si caducó) · 404 |
| `GET /trust/manifest` | público | — | 200 `TrustManifestResponse` · 503 si no hay manifiesto cargado |
| `POST /admin/issuers` | — | — | **404** (retirado por D-1) |

**Ninguna escritura es pública.** Las lecturas públicas siguen pasando por el rate limit global.

## Publicación atómica (`POST /drafts/:id/publish`)

1. Controles: rate limit → autenticación → CSRF → Zod → RBAC → propiedad → cuota de publicación.
2. Si el borrador ya está `PUBLISHED` → 409.
3. Se construye la petición ALERTA (`alerta_id` nuevo, `emisor_id` = dueño, campos del borrador y fechas) y se firma
   **fuera** de la transacción. Si el firmante falla → 503, se audita `PUBLICATION_FAILED` y **no se escribe nada más**.
4. En una sola transacción: `INSERT` de la alerta (bytes exactos, hash, firma y key_id), `INSERT` del ESTADO inicial
   firmado (VIGENTE, secuencia 0), `UPDATE` del borrador a `PUBLISHED` con su `alertaId` y `INSERT` de la auditoría
   `ALERT_PUBLISHED`. Si algo falla → rollback completo.
5. El ESTADO se firma también **antes** de la transacción. Firmar es idempotente respecto a la BD.

## Cancelación (`POST /alerts/:id/cancel`)

1. Controles + propiedad: `alerta.emisor_id === usuario`. Si no → 403 y `CANCEL_DENIED` (P02c).
2. Si ya existe un EVENTO de cancelación → 409.
3. Se firma el EVENTO (`hash_alerta` = `hash_payload` de la alerta) y el nuevo ESTADO (CANCELADA, `secuencia` + 1,
   `ultimo_evento_hash` = hash del EVENTO), ambos fuera de la transacción.
4. Transacción: `INSERT` del evento, `INSERT` del estado y `INSERT` de la auditoría `ALERT_CANCELLED`.

## Estado firmado

- Se sirve el último ESTADO guardado si `expires_at` está a más de 30 s. Si no, se firma uno nuevo con el mismo
  contenido, nuevas fechas `issued_at` y `expires_at` (+600 s) y se guarda (solo `INSERT`).
- El valor `VENCIDA` se usa cuando `ahora ≥ expira_en` de la alerta y no hay cancelación.

## Base de datos y roles SQL

| Rol | Uso | Permisos |
| --- | --- | --- |
| `alertasegura` (propietario) | Migraciones (`DATABASE_MIGRATION_URL`) y seed | Todo |
| `alertasegura_app` | API en ejecución (`DATABASE_URL`) | `SELECT, INSERT` en alertas publicadas, eventos, estados, claves públicas y auditoría; `SELECT, INSERT, UPDATE` en borradores y usuarios; `SELECT, INSERT, UPDATE, DELETE` en sesiones. **Nunca** UPDATE/DELETE/TRUNCATE en publicadas, eventos, estados ni auditoría (P07) |

La contraseña del rol app vive solo en `.env` (`APP_DB_PASSWORD`). La crea un script idempotente (`pnpm db:roles`),
no una migración.

## Firmante

- HTTP sobre **socket Unix** (`SIGNER_SOCKET_PATH`, por defecto `/run/signer/signer.sock`): `POST /sign` y `GET /health`.
- La API usa un timeout de 3 s; cualquier error → `SIGNER_UNAVAILABLE` (503).
- Solo los contenedores `api` y `signer` montan el volumen del socket. La clave privada solo se monta en `signer`
  (0400, usuario 10001). La API corre como usuario 10002 (P15).

## Nuevos eventos de auditoría

`ALERT_PUBLISHED`, `PUBLICATION_FAILED`, `ALERT_CANCELLED`, `CANCEL_DENIED`, `CANCEL_FAILED` y `DRAFT_UPDATED`.
`PUBLICATION_AUTHORIZED` deja de emitirse; solo se conserva para leer registros antiguos.

## Códigos de error

Sale `PUBLICATION_NOT_IMPLEMENTED` y entra `SIGNER_UNAVAILABLE` (503).
