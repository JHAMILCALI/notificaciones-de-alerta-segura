# Reporte de cumplimiento — Semana 2 (GATE G2)

- **Validación final:** 2026-10-26 (UTC). La elaboró ATLAS a partir de ejecuciones reales; cada resultado enlaza su
  evidencia.
- **Entorno:** Windows 11, Node 24.14.0, pnpm 12.14.0 y Docker 29.4.0. Pila `docker compose --profile g2`:
  `postgres:17-alpine`, `migrate`, `signer` (usuario 10001) y `api` (usuario 10002).
- **Referencia oficial:** `AlertaSegura_Propuesta_Definitiva_Seguridad_4_Semanas.pdf`, sección 11: «G2 · P02c, P03 API,
  P06 backend, P07, P15 y P16».
- **Equipo:**
  - ATLAS: orquestación, contratos, revisión, integración y aceptación.
  - SHIRO: backend, base de datos y Docker de la API.
  - MOTO: firmante, CLI de confianza, verificación y web.

## Resultado del GATE G2: **APROBADO**

Las pruebas se ejecutaron **contra la pila Docker real**: la API con el rol SQL limitado y el firmante aislado con la
clave del laboratorio, y la verificación se hizo con la clave pública que publica el **manifiesto firmado por la raíz**.

La aceptación de caja negra la escribió ATLAS y es independiente de las pruebas de los agentes.

| Prueba | Resultado obligatorio (sección 10) | Caja negra (ATLAS) | Pruebas de los agentes | Estado |
| --- | --- | --- | --- | --- |
| **P02c** | El emisor A cancela una alerta del emisor B → 403 por propiedad; operación auditada | [`P02c.json`](g2/P02c.json) **6/6** | e2e de SHIRO (`s2-21..24`) | **APROBADO** |
| **P03 (API)** | Se altera mensaje, fecha o severidad → la firma falla | [`P03.json`](g2/P03.json) **8/8** | Vectores de MOTO | **APROBADO** |
| **P06 (backend)** | Cancelación válida / evento falsificado + historial | [`P06.json`](g2/P06.json) **9/9** | `verifyCancelacion` (MOTO), e2e (SHIRO) | **APROBADO** |
| **P07** | UPDATE/DELETE sobre publicaciones con el rol app → privilegio denegado | [`P07.json`](g2/P07.json) **20/20** | [`p07-rol-app.txt`](g2/p07-rol-app.txt) (SHIRO) | **APROBADO** |
| **P15** | El usuario del proceso API intenta leer la clave de firma → EACCES | [`P15.json`](g2/P15.json) **6/6** ([salida](g2/P15-salida.txt)) | [`p15-api.txt`](g2/p15-api.txt) (SHIRO), prueba del firmante (MOTO) | **APROBADO** |
| **P16** | Sustituir la firma de un EVENTO por la de una ALERTA → rechazo por `tipo_doc` o bytes | [`P16.json`](g2/P16.json) **6/6** | `p16-vectors.json` (MOTO) | **APROBADO** |

**Totales:**
- Aceptación G2: **55/55** comprobaciones ([log](g2/logs/g2-acceptance.log)).
- Regresión G1: **38/38** ([log](g2/logs/regresion-g1.log)).
- P13: **46/46** ([log](g2/logs/regresion-p13.log)).
- Suite integrada: **342/342** unitarias y **169/169** e2e ([log](g2/logs/suite-integrada.log)).

---

### P02c — Un emisor no puede cancelar alertas ajenas

- **Preparación:**
  - Dos emisores nuevos dados de alta con `pnpm lab issuer:add`, el comando de laboratorio de D-1.
  - El emisor A publica una alerta (201).
- **Pasos:** intentan cancelar la alerta el emisor B, el ADMIN y un usuario anónimo; después se consulta la auditoría
  y el estado firmado.
- **Observado:**
  - El emisor B recibe 403 FORBIDDEN.
  - El ADMIN recibe 403, porque no tiene `alerts:cancel`.
  - El anónimo recibe 401.
  - Queda registrado `CANCEL_DENIED` con el `actorId` del emisor B.
  - El ESTADO firmado (verificado) sigue **VIGENTE** y sin eventos.

### P03 — Alterar la alerta invalida la firma

- **Control:** la alerta servida por `GET /alerts/:id` verifica con la clave activa del manifiesto (GRANIZADA, LA_PAZ,
  NARANJA).
- **Alteraciones:** se modificó el documento, se re-canonicalizó, se recalculó el hash y se **conservó la firma
  original**.

  | Alteración | Resultado |
  | --- | --- |
  | `mensaje` cambiado a «EVACUACIÓN INMEDIATA» | `SIGNATURE_INVALID` |
  | `expira_en` adelantada 3 días | `SIGNATURE_INVALID` |
  | `severidad` NARANJA → ROJA | `SIGNATURE_INVALID` |
  | `zona.departamento` cambiado | `SIGNATURE_INVALID` |
  | Mensaje cambiado sin recalcular `hash_payload` | `HASH_MISMATCH` |
- **Base de datos:** la columna `payloadCanonico` (bytea) contiene **exactamente** los bytes firmados. Además,
  `hashPayload` coincide con el `sha256()` calculado por PostgreSQL y con el sobre que entrega la API.

### P06 — Cancelación válida, eventos falsificados e historial

- **Cancelación legítima:** el dueño cancela y recibe 201.
  - `verifyCancelacion` acepta el EVENTO: su `hash_alerta` es el SHA-256 de los bytes exactos de la alerta.
  - El ESTADO firmado queda **CANCELADA**, con `secuencia` 1 y `ultimo_evento_hash` igual al hash del evento.
  - Su frescura es de 600 s.
  - Cancelar por segunda vez devuelve 409.
  - El historial (1 evento) es visible en la consulta pública.
- **Falsificaciones rechazadas:**
  - Un evento **legítimo de otra alerta** → `CANCELACION_ALERTA_MISMATCH`.
  - Un `hash_alerta` alterado → `SIGNATURE_INVALID`.
  - Un evento bien formado **firmado con una clave ajena** → `KEY_ID_MISMATCH`.
  - Ese mismo evento haciéndose pasar por la clave activa → `SIGNATURE_INVALID`.

### P07 — El rol de la aplicación no puede modificar lo publicado

- **Control positivo:** el rol `alertasegura_app` **sí** puede leer la alerta (`SELECT` → 1).
- **Intentos denegados:** se probaron `UPDATE`, `DELETE` y `TRUNCATE` sobre `AlertaPublicada`, `EventoAlerta`,
  `EstadoAlerta`, `AuditLog` y `ClavePublica`. Las **15 sentencias** fallaron con `permission denied for table …`.
- **La API no ofrece otra vía:** `PUT`, `PATCH` y `DELETE /alerts/:id` responden 404.
- **Resultado:** la alerta conserva su hash original.

### P15 — La API no puede leer la clave del firmante

El script `infra/scripts/p15-api-isolation.sh` (de SHIRO) se ejecutó contra el contenedor en marcha:

| # | Comprobación | Resultado |
| --- | --- | --- |
| A1 | Usuario del contenedor `api` | 10002, con el grupo 10001 solo para el socket |
| A2 | Montajes del contenedor `api` | Solo `/run/signer` y el manifiesto; ninguna ruta de secretos |
| A3 | `fs.readFileSync('/run/secrets/signer-private-key.pem')` desde `api` | `ENOENT` |
| B | La misma lectura con la clave montada con permisos reales de Linux (10001:10001, 0400) | `EACCES` |
| C | Control: el usuario 10001 (el firmante) lee esa misma clave | `LEIDA` |

**Comprobación adicional del socket en Linux** ([`socket-linux.txt`](g2/logs/socket-linux.txt)). Son las 2 pruebas
del firmante que Vitest omite en Windows:
- El socket es `srw-rw----` (0660, 10001:10001) y su directorio, 0750.
- Al reiniciar el firmante, el servicio vuelve a estar sano reutilizando la ruta del socket.
- Un contenedor **sin** el grupo 10001 recibe `EACCES` al conectar, y el mismo contenedor **con** el grupo conecta (200).

### P16 — Separación de tipos de documento

La prueba usa **documentos reales** de la API (no solo vectores):

| Mezcla | Resultado |
| --- | --- |
| EVENTO real presentado como ALERTA | `TIPO_DOC_MISMATCH` |
| ALERTA real presentada como EVENTO | `TIPO_DOC_MISMATCH` |
| ESTADO real presentado como EVENTO | `TIPO_DOC_MISMATCH` |
| Bytes de la ALERTA con la firma del EVENTO, y al revés | `SIGNATURE_INVALID` |
| `tipo_doc` del EVENTO reescrito a ALERTA, con la firma original | `SIGNATURE_INVALID` |

### Regresión de la semana 1

Se ejecutó `g1-acceptance.mjs`, actualizado al contrato de la semana 2, contra la misma pila Docker:

| Prueba | Resultado |
| --- | --- |
| P01 | **18/18** |
| P02a | **4/4** |
| P02b | **10/10**. El control positivo ahora **publica** (201) y se audita `ALERT_PUBLISHED` |
| P09 | **6/6** |
| P13 | **46/46** |

Además, P01 comprueba que `POST /admin/issuers` responde 404 (D-1) y que el alta de emisores queda auditada con el
actor `lab-script`. Evidencia: [`regresion-g1/`](g2/regresion-g1/). La evidencia de cierre de la semana 1
(`docs/evidence/g1/`) se conserva sin cambios.

---

## Entregables de la semana 2 (sección 11)

| Día | Entregable | Responsable | Estado |
| --- | --- | --- | --- |
| D6 | Proceso firmante aislado (socket, usuario propio, valida y firma solo ALERTA, EVENTO y ESTADO) | MOTO | ✅ |
| D7 | Publicación atómica: firma fuera de la transacción y alerta + estado + auditoría en una sola transacción | SHIRO | ✅ |
| D8 | Cancelación por EVENTO firmado con `hash_alerta` | SHIRO + MOTO | ✅ |
| D9 | CLI de confianza: `init-root`, `keygen-signer`, `issue-manifest`, `revoke` y `rotate` | MOTO | ✅ Manifiesto v1 emitido y servido por la API |
| D10 | Estado firmado inicial (frescura de 10 min) y backend | SHIRO | ✅ |
| — | Rol SQL `alertasegura_app` sin UPDATE/DELETE/TRUNCATE en publicadas, eventos, estados y auditoría | SHIRO | ✅ |

**Además, de la política del plan:**

| Tarea | Prioridad | Estado |
| --- | --- | --- |
| Cuota de publicación por emisor (S2-26) | MEDIA | ✅ |
| Inventario de claves públicas (S2-25) | MEDIA | ✅ |
| TLS de laboratorio con mkcert (S2-45) | MEDIA | ✅ en código; demostración con certificado pendiente |
| Purga de sesiones y CSP (S2-48) | BAJA | ✅ |
| Rutas `/admin` y `/alertas` (D-3) | BAJA | ✅ |
| Botón Cancelar en la web | MEDIA | ✅ |
| Recorrido en Chrome publicando y cancelando (S2-47) | BAJA | ⏳ No ejecutado: el recorrido de la semana 1 usa selectores del formulario anterior y hay que adaptarlo |

## Decisiones aplicadas (D-1 a D-6)

| # | Decisión |
| --- | --- |
| D-1 | Alta de emisores con el comando de laboratorio `pnpm lab issuer:add`, auditado como `lab-script`; `POST /admin/issuers` retirado (404) |
| D-2 | Rol AUDITOR mantenido (solo `audit:read`) |
| D-3 | Rutas `/admin` y `/alertas` con redirecciones |
| D-4 | Opción C adaptada a **Bolivia**: 9 departamentos, 14 tipos de fenómeno, niveles amarilla/naranja/roja, vigencia de 1 a 72 h y hora `America/La_Paz` |
| D-5 | TLS de laboratorio implementado (falta la demostración con certificado) |
| D-6 | NestJS sobre Express, documentado |

## Revisión de las entregas

Detalle en [`revision-semana2-registro.md`](../coordination/revision-semana2-registro.md).

- **Revisadas y fusionadas** con `--no-ff`: 3 ramas (`s2/moto`, `s2/shiro` y la entrega 6 de SHIRO).
- **Pruebas:** ATLAS repitió en cada worktree las pruebas que reportaban los agentes y **coincidieron todas**.
- **Hallazgos:** 0 altos, 0 medios y 1 bajo (H-1: `verifyManifest` no rechaza un `issued_at` futuro; queda para la
  semana 3).
- **Secretos:** ninguna clave privada ni secreto en el historial de la semana ni en las evidencias. Se comprobaron
  los 7 valores secretos del `.env` y los patrones de clave PEM y JWK.

**Incidencias de ATLAS durante la validación, corregidas:**
- El `g1-acceptance` sobrescribió la evidencia de la semana 1. Se restauró desde Git y el script tiene ahora `--out`.
- La primera prueba del socket con `docker exec` daba un falso «conecta», porque `exec` hereda el `group_add`. Se
  repitió con un contenedor limpio.

## Matriz T1–T11 tras la semana 2

Detalle en [`docs/threat-model`](../threat-model/README.md).

| Estado | Amenazas |
| --- | --- |
| **Mitigado** | T1, T6, T8, T10 |
| **Parcial** (control probado; falta la prueba de la PWA o de un gate posterior) | T2 (P11), T3 (P04, P14), T4 (P05), T5 (P06 en la PWA), T7 (P08), T11 (P06b) |
| **Pendiente** | T9 (P10, semana 3) |

## Pendiente para la semana 3 (G3)

- **Verificador de la PWA** (`/alertas`):
  - listado, detalle y evidencia de la verificación;
  - estados VIGENTE, VENCIDA, CANCELADA, MANIPULADA, NO CONFIABLE y NO COMPROBABLE;
  - raíz anclada en el bundle y versión mínima del manifiesto persistida.
- **Pruebas P04, P05, P06** (en la PWA), **P06b, P08, P08b, P10 y P11**.
- **HMAC encadenado y checkpoint externo** de la auditoría.
- **Hallazgo H-1** y el recorrido en Chrome de publicar y cancelar.

## Cómo reproducir

```bash
# Claves y manifiesto de laboratorio (la raíz queda fuera del repositorio)
node tools/trust-cli/src/main.ts init-root
node tools/trust-cli/src/main.ts keygen-signer --out secrets/signer
node tools/trust-cli/src/main.ts issue-manifest --version 1 --hours 24 \
  --signer-jwk secrets/signer/public.jwk.json --issuers <uuid-emisor1>,<uuid-emisor2> --out secrets/manifest.json

# .env: SIGNER_PRIVATE_KEY_FILE=../secrets/signer/private.pem · TRUST_MANIFEST_HOST_FILE=../secrets/manifest.json
docker compose -f infra/compose.yml --env-file .env --profile g2 up -d --build --wait

node tests/security/g2-acceptance.mjs                                   # P02c, P03, P06, P07, P15, P16
node tests/security/g1-acceptance.mjs --out docs/evidence/g2/regresion-g1   # regresión P01, P02a, P02b, P09
pnpm --filter @alertasegura/verification exec vitest run -t P13
pnpm build && pnpm typecheck && pnpm lint && pnpm test && pnpm test:e2e
```
