# Ficha de MOTO — Semana 2 (criptografía, firmante, CLI de confianza y web)

**Worktree:** `C:\2026-2\Tecnico superior\alertasegura\.worktrees\moto` · **Rama:** `s2/moto`
**BD local:** `alertasegura_moto` (`localhost:5433`) · **API de pruebas:** puerto 3200
**Contratos:** `packages/shared/src` (solo ATLAS los edita): sobre todo `schemas/documents.ts`, `schemas/signer.ts` y
`constants/bolivia.ts`. Ver también [`api-contract-semana2.md`](api-contract-semana2.md).
**Plan:** [`../plan-semana2.md`](../plan-semana2.md)

## Tus carpetas

`apps/signer`, `tools/trust-cli`, `packages/verification`, `apps/web`, `infra/docker/signer.Dockerfile` y
`tests/fixtures/crypto/`. No edites `packages/shared`, `apps/api`, `packages/database` ni `infra/compose.yml`.

## Antes de empezar

```bash
git merge feat/semana-2          # trae los contratos de la fase 0
pnpm install && pnpm build:packages
```

`apps/web` **no compilará** hasta que adaptes el formulario de borradores (D-4) y los códigos de error. Es lo esperado.

## Reglas criptográficas (no negociables)

- ECDSA P-256 + SHA-256; firma **IEEE P1363** de 64 bytes en base64url (`dsaEncoding: 'ieee-p1363'` en Node).
- Canonicalización **JCS RFC 8785** con el `canonicalize` de `packages/verification`: una sola implementación para
  firmar y verificar.
- `key_id` = SHA-256 (base64url) de la SPKI (`computeKid`).
- Fechas normalizadas a ISO 8601 UTC con segundos **antes** de canonicalizar.
- **Claves privadas:** jamás en el repositorio, en `apps/web` ni en la API.
  - La clave del firmante va en `secrets/` (ignorada por Git), en modo 0400 donde el sistema lo permita.
  - La clave raíz va **fuera del repositorio**: por defecto `~/.alertasegura-lab/root/`, configurable con `--root-dir`.
- Los vectores de prueba se generan con claves **efímeras** que se descartan; solo se versionan las claves públicas y
  las firmas.

## Entregas, en este orden

### Entrega 1 · CLI de confianza y verificación por tipo (ALTA)

| ID | Tarea | Aceptación |
| --- | --- | --- |
| S2-14 | `tools/trust-cli` con los comandos de abajo | Tests unitarios de cada comando; un manifiesto emitido verifica con `verifyManifest`; una versión menor o igual a la anterior se rechaza al emitir; nada privado se escribe dentro del repositorio salvo en `secrets/` |
| S2-17 | `packages/verification`: añadir `verifyDocument({ envelope, jwk, tipoEsperado })` y `verifyManifest({ envelope, rootJwk, ahora, versionMinima })` | Tests en verde; **P13 sigue 46/46**; las funciones nuevas no aceptan JWK con `d` |

Comandos de la CLI (S2-14):
- `init-root`: genera la raíz P-256 en `--root-dir`, fuera del repositorio.
- `keygen-signer --out secrets/signer`: genera la clave del firmante. Guarda la privada en PKCS#8 PEM y la pública en JWK,
  e imprime el `key_id`.
- `issue-manifest --version N --hours 24 --signer-jwk … --issuers uuid,uuid --out secrets/manifest.json`: emite el
  documento `MANIFIESTO` firmado por la raíz, como sobre `SignedEnvelope`. La vigencia es como máximo de 7 días.
- `revoke --key-id … --version N+1`: emite un manifiesto nuevo con esa clave en `revocadas`.
- `rotate --version N+1`: genera una clave nueva del firmante, la activa y deja la anterior revocada o retirada.

Qué comprueba cada función nueva de verificación (S2-17):
- **`verifyDocument`:** verifica la firma sobre los bytes de `payload_canonico`. Comprueba que `hash_payload` = SHA-256 de
  esos bytes, que el `key_id` del sobre coincide con el del payload y con el `computeKid` de la JWK, y que `tipo_doc` es
  el esperado. Después valida el payload con el esquema Zod de su tipo. Devuelve el documento solo si todo pasa.
- **`verifyManifest`:** verifica con la raíz anclada y comprueba que `expires_at` está en el futuro, que la vigencia no
  pasa de 7 días y que `version` ≥ `versionMinima`.

### Entrega 2 · Firmante aislado (ALTA)

| ID | Tarea | Aceptación |
| --- | --- | --- |
| S2-15 | `apps/signer`: servidor HTTP en `SIGNER_SOCKET_PATH`. En Linux es un socket Unix y fija el permiso 0660 al crearlo; en Windows, una named pipe para desarrollo. Ofrece `POST /sign` y `GET /health`. Valida con `SignRequestSchema` (estricto), añade `key_id`, normaliza fechas, canonicaliza, firma y responde `SignResponseSchema`. Lee la clave de `SIGNER_PRIVATE_KEY_PATH` **una sola vez** al arrancar. Rechaza `MANIFIESTO` y cualquier `tipo_doc` desconocido, cuerpos de más de 16 kB y JSON inválido. No registra nunca el payload completo ni la clave | Tests: alerta, evento y estado válidos verifican con `verifyDocument`; campo extra → 400; fechas con milisegundos → normalizadas o rechazadas según el contrato; clave ausente → 503 `KEY_UNAVAILABLE` |
| — | `infra/docker/signer.Dockerfile`: usuario 10001, sistema de archivos de solo lectura, el socket en un volumen `/run/signer` y la clave en `/run/secrets/signer-private-key.pem` (0400) | La imagen construye; el contenedor arranca con la clave montada y `/health` responde por el socket |

### Entrega 3 · Web con los campos nuevos y vectores P16 (ALTA)

| ID | Tarea | Aceptación |
| --- | --- | --- |
| S2-11 | Formulario de borradores con `tipo` (lista de `TIPO_ALERTA_ETIQUETAS`), `departamento` (`DEPARTAMENTO_ETIQUETAS`), municipio opcional, nivel (amarilla, naranja o roja, con su color), mensaje y vigencia en horas (1–72). Fechas mostradas en `America/La_Paz` con `es-BO`. El botón publicar trata el **201** (muestra el id de la alerta) y el **503** del firmante. Elimina `PUBLICATION_NOT_IMPLEMENTED` | Tests de la web en verde; recorrido manual contra la API de SHIRO cuando esté |
| S2-35 | Vectores P16 en `tests/fixtures/crypto/p16-vectors.json` y pruebas: la firma de un EVENTO puesta en una ALERTA (y al revés), ESTADO como EVENTO, un payload con `tipo_doc` cambiado, y la mezcla de bytes de un documento con la firma de otro | Todos rechazados por `verifyDocument`, indicando el motivo (`tipo_doc` o firma) |
| S2-32 | Apoyo a P06: vectores de eventos falsificados (otra clave, `hash_alerta` que no coincide, firma de ALERTA) | Rechazo en `verification`; la comprobación de `hash_alerta` contra la alerta va en una función `verifyCancelacion(alertaEnvelope, eventoEnvelope, jwk)` |

### Entrega 4 · Apoyo a G2 y extras

| ID | Tarea | Prioridad |
| --- | --- | --- |
| S2-34 | P15: con SHIRO, que la ruta de la clave no sea legible por el usuario 10002 (permisos del Dockerfile y del compose) | ALTA |
| — | En la página de borradores: botón **Cancelar** para los borradores publicados (usa `alertaId` y `POST /alerts/:id/cancel`) | MEDIA |
| S2-45 | TLS de laboratorio en Vite (`mkcert`), con el proxy a la API por HTTPS cuando corresponda | MEDIA |
| S2-46 | D-3: rutas `/admin` (panel con sesión) y `/alertas` (consulta ciudadana), con redirecciones desde `/panel` y `/` | BAJA |

## Cómo coordinarte con SHIRO

- **Firmante:** SHIRO programa el cliente contra el **mismo contrato** (`schemas/signer.ts`). Cualquier duda o cambio
  de protocolo se pide a ATLAS, no se negocia directamente.
- **Docker:** el Dockerfile del firmante es tuyo; el compose y la API son de SHIRO.

## Reglas

1. **Commits pequeños** en `s2/moto` (mensajes en español, estilo `feat(signer): …`), terminados con
   `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Sin push, sin cambiar de rama, sin fusionar.
2. **Nada falso:** no marques nada como aprobado sin ejecutarlo y no desactives pruebas ni reglas de lint.
3. **Ninguna clave privada** en los commits. Antes de cada commit ejecuta
   `git diff --cached | grep -iE "BEGIN (EC )?PRIVATE|\"d\":"`, que no debe encontrar nada.
4. **Al terminar cada entrega**, avisa a ATLAS por SendMessage con: commits (hash y título), comandos ejecutados con su
   resultado, decisiones tomadas y temas abiertos.
