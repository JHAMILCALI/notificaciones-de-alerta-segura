# Ficha de SHIRO — Semana 2 (backend y base de datos)

**Worktree:** `C:\2026-2\Tecnico superior\alertasegura\.worktrees\shiro` · **Rama:** `s2/shiro`
**BD local:** `alertasegura_shiro` (`localhost:5433`) · **API:** puerto 3100
**Contratos:** `packages/shared/src` (solo ATLAS los edita) y [`api-contract-semana2.md`](api-contract-semana2.md)
**Plan:** [`../plan-semana2.md`](../plan-semana2.md)

## Tus carpetas

`apps/api`, `packages/database`, `infra/compose.yml` y el Dockerfile nuevo de la API (`infra/docker/api.Dockerfile`).
No edites `packages/shared`, `apps/signer`, `tools/trust-cli`, `packages/verification` ni `apps/web`.

## Antes de empezar

```bash
git merge feat/semana-2          # trae los contratos de la fase 0
pnpm install && pnpm build:packages
```

`apps/api` **no compilará** hasta que adaptes el borrador (D-4), el retiro de `issuers:provision` (D-1) y el fin de
`PUBLICATION_NOT_IMPLEMENTED`. Es lo esperado: tu entrega 1 lo arregla.

## Entregas, en este orden

### Entrega 1 · D-4 y D-1 (ALTA) — vuelve a dejar la semana 1 en verde

| ID | Tarea | Aceptación |
| --- | --- | --- |
| S2-10 | Migración de `Draft` a los campos oficiales: `tipo`, `zona` (`departamento`, `municipio` nullable), `severidad` (AMARILLA/NARANJA/ROJA), `mensaje`, `vigenciaHoras`, `status` (DRAFT/PUBLISHED) y `alertaId` nullable. Migra los borradores existentes: INFO→AMARILLA, WARNING→NARANJA, CRITICAL→ROJA, `title + body` → `mensaje`, tipo `LLUVIAS_INTENSAS`, departamento `LA_PAZ` y vigencia de 24 h. Actualiza el seed con 2 borradores bolivianos de ejemplo | `db:deploy` en una BD nueva y en `alertasegura_shiro`; e2e de borradores en verde |
| S2-16 | D-1: retira `POST /admin/issuers` (→ 404). Crea el comando de laboratorio `pnpm lab issuer:add --email --name` en `packages/database` (script local con el rol propietario). Pide la contraseña por stdin o por `LAB_ISSUER_PASSWORD`, nunca por argumento. Audita `ISSUER_PROVISIONED` con `actorId = null` y `metadata.actor = "lab-script"` | Las e2e de P01 y de provisión adaptadas (el endpoint da 404 y el script crea y audita); P01, P02a, P02b y P09 en verde |
| — | Publicar sigue respondiendo 501 hasta la entrega 3. Para compilar, usa el código `SIGNER_UNAVAILABLE` o deja un 501 local; se elimina en la entrega 3 | `pnpm --filter @alertasegura/api typecheck`, `lint`, `test` y `test:e2e` en verde |

### Entrega 2 · Tablas inmutables y rol SQL (ALTA)

| ID | Tarea | Aceptación |
| --- | --- | --- |
| S2-12 | Modelos `AlertaPublicada` (`id`, `emisorId`, `draftId` único, `payloadCanonico Bytes`, `hashPayload`, `firma`, `keyId`, `publishedAt`, columnas de resumen para listar), `EventoAlerta` (`id`, `alertaId`, `payloadCanonico Bytes`, `hashEvento`, `hashAlerta`, `firma`, `keyId`, `createdAt`; **una cancelación por alerta**), `EstadoAlerta` (solo INSERT: `alertaId`, `secuencia`, `payloadCanonico`, `hashPayload`, `firma`, `keyId`, `expiresAt`) y `ClavePublica` (`keyId`, `jwk`, `versionRegistro`, `creadoEn`) | Migración aplicada; FKs, índices y unicidades revisados |
| S2-13 | Script idempotente `pnpm db:roles` que crea o actualiza `alertasegura_app` con la contraseña `APP_DB_PASSWORD` del `.env`. Permisos según `api-contract-semana2.md`, más `ALTER DEFAULT PRIVILEGES` para tablas futuras. Separar `DATABASE_MIGRATION_URL` (propietario) y `DATABASE_URL` (app). Actualizar `.env.example` y la guía | Con el rol app: `UPDATE`/`DELETE`/`TRUNCATE` en las 4 tablas protegidas → 42501; la API funciona con el rol app |

### Entrega 3 · Publicar, cancelar, estado y lecturas públicas (ALTA)

| ID | Tarea | Aceptación |
| --- | --- | --- |
| S2-20 | Cliente del firmante: HTTP sobre `SIGNER_SOCKET_PATH` (en Windows sirve una named pipe `\\.\pipe\alertasegura-signer`), timeout de 3 s, valida la respuesta con `SignResponseSchema`; cualquier fallo → `SIGNER_UNAVAILABLE` | Tests con un **firmante falso de prueba** (clave efímera generada en el test, mismo contrato) y caídas simuladas |
| S2-21 | Publicación atómica según `api-contract-semana2.md` | e2e: 201 con los bytes guardados idénticos a `payload_canonico`, `hash_payload` correcto y firma verificable con `@alertasegura/verification`; firmante caído → 503 sin filas nuevas y el borrador sigue en DRAFT; fallo forzado de la auditoría → rollback; publicar dos veces → 409 |
| S2-22 | Cancelación con propiedad (P02c) | e2e: el dueño → 201; el emisor B → 403 y `CANCEL_DENIED`; dos veces → 409; ADMIN y AUDITOR → 403 |
| S2-23 | Estado firmado: inicial VIGENTE con secuencia 0; CANCELADA con secuencia 1; regeneración al caducar; VENCIDA tras `expira_en` | e2e con reloj controlado (`jest.useFakeTimers` o reloj inyectable) |
| S2-24 | `GET /alerts`, `GET /alerts/:id` y `GET /trust/manifest` (lee `TRUST_MANIFEST_FILE`; si falta → 503) | e2e anónimo; ningún endpoint público de escritura |

### Entrega 4 · Docker de la semana 2 y pruebas G2 (ALTA)

| ID | Tarea | Aceptación |
| --- | --- | --- |
| S2-27 | `infra/docker/api.Dockerfile` (usuario 10002) y perfil `g2` en `compose.yml`: `postgres` + `signer` (Dockerfile de MOTO) + `api`; volumen `signer_socket` compartido (0660, grupo común); clave montada **solo** en `signer` | `docker compose -f infra/compose.yml --profile g2 up` levanta todo; `/health` OK; publicar funciona de punta a punta |
| S2-30 | P02c e2e | Ver entrega 3 |
| S2-33 | P07: prueba e2e o script que conecta como `alertasegura_app` e intenta `UPDATE`/`DELETE` en publicadas, eventos, estados y auditoría | 42501 en todas las sentencias; salida guardada como evidencia |
| S2-34 | P15 (con MOTO): desde el contenedor `api`, `node -e "fs.readFileSync('/run/secrets/signer-private-key.pem')"` | `EACCES` o `ENOENT` por no estar montada; documenta cuál y por qué. Lo ideal: montada en otra ruta sin permiso → `EACCES` |

### Entrega 5 · MEDIA y BAJA (solo con G2 encaminado)

| ID | Tarea | Prioridad |
| --- | --- | --- |
| S2-25 | Inventario `ClavePublica` a partir del manifiesto al arrancar (solo INSERT de las claves nuevas) | MEDIA |
| S2-26 | Cuota de publicación por emisor (`RATE_PUBLISH_LIMIT`, por defecto 10 por hora) → 429 | MEDIA |
| S2-45 | TLS de laboratorio (parte de la API: `COOKIE_SECURE=true` detrás de HTTPS) | MEDIA |
| S2-48 | Purga de sesiones caducadas y CSP | BAJA |

## Cómo coordinarte con MOTO

- **Firmante:** MOTO implementa el servidor con el **mismo** `SignRequestSchema` y `SignResponseSchema`. Hasta que esté
  listo, usa tu firmante falso de pruebas. No dependas de su código, solo del contrato.
- **Dockerfile del firmante:** es de MOTO; el compose y el Dockerfile de la API son tuyos.
- **Si necesitas algo del otro agente o un cambio de contrato,** pídeselo a ATLAS.

## Reglas

1. **Commits pequeños** en `s2/shiro` (mensajes en español, estilo `feat(api): …`), terminados con
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Sin push, sin cambiar de rama, sin fusionar.
2. **Nada falso:** no marques nada como aprobado sin ejecutarlo y no desactives reglas de lint ni pruebas.
3. **Ni secretos ni claves** en el repositorio. El `.env` es local.
4. **Al terminar cada entrega**, avisa a ATLAS por SendMessage con: commits (hash y título), comandos ejecutados con su
   resultado (número de tests y estado), decisiones tomadas y temas abiertos.
