# Guía de revisión — Semana 2 (trabajo de SHIRO y MOTO)

Cómo revisar lo que entregaron los agentes antes de fusionarlo en `feat/semana-2`, y cómo lo hace ATLAS paso a paso.
Sirve para el orquestador y también para que el autor revise por su cuenta.

> **Principio:** revisar no es leer el reporte del agente. Un resultado solo cuenta si **lo ejecuta quien revisa**.
> Lo que el agente reporta se trata como una afirmación por comprobar, no como evidencia.

| Rama | Agente | Commits | Tamaño |
| --- | --- | --- | --- |
| `s2/moto` | MOTO: firmante, trust-cli, verificación, web | 11 | 54 archivos, unas 4100 líneas |
| `s2/shiro` | SHIRO: base de datos, roles SQL, API, Docker | 12 | 73 archivos, unas 5400 líneas |

---

## 1. Orden de la revisión

```mermaid
flowchart TD
    A["1 · Inventario<br/>qué entregó cada uno"] --> B["2 · Controles automáticos<br/>propiedad, secretos, contratos, trampas"]
    B --> C["3 · Lectura del código crítico<br/>con la lista de cada agente"]
    C --> D["4 · Pruebas en su worktree<br/>build, lint, tests"]
    D --> E{"¿Hallazgos<br/>ALTOS?"}
    E -- Sí --> F["Corrección al agente<br/>(SendMessage)"] --> G["Revisar solo el cambio nuevo"] --> D
    E -- No --> H["5 · Fusión --no-ff<br/>primero MOTO, después SHIRO"]
    H --> I["6 · Verificación integrada<br/>suite completa en la raíz"]
    I --> J["7 · Aceptación G2<br/>caja negra + Docker + evidencias"]
    J --> K["8 · Registro de revisión<br/>y reporte de cumplimiento"]
```

**Primero MOTO y después SHIRO.** El perfil Docker de SHIRO usa el firmante y el Dockerfile de MOTO. Fusionando primero
a MOTO, la rama de integración ya tiene el firmante real cuando llega la API.

---

## 2. Inventario: qué entregó cada uno

Desde la raíz del repositorio:

```bash
git fetch --all 2>/dev/null; git worktree list
git log --oneline feat/semana-2..s2/moto
git log --oneline feat/semana-2..s2/shiro
git diff --stat feat/semana-2...s2/moto | tail -1
git diff --stat feat/semana-2...s2/shiro | tail -1
git -C .worktrees/moto status --short     # debe estar vacío: nada sin commit
git -C .worktrees/shiro status --short
```

Compara cada commit con la ficha del agente (`moto-semana2.md`, `shiro-semana2.md`): cada tarea S2-xx debe tener uno o
más commits que la mencionen. **Si falta alguna tarea ALTA, no se fusiona.**

---

## 3. Controles automáticos (antes de leer código)

Se ejecutan sobre cada rama y son baratos. Cualquier resultado inesperado se convierte en hallazgo.

### 3.1 Propiedad de archivos

```bash
git diff --name-only feat/semana-2...s2/moto
git diff --name-only feat/semana-2...s2/shiro
```

| Agente | Puede tocar | Todo lo demás es un hallazgo |
| --- | --- | --- |
| MOTO | `apps/signer`, `tools/trust-cli`, `packages/verification`, `apps/web`, `infra/docker/signer.Dockerfile`, `tests/fixtures/crypto`, `pnpm-lock.yaml` (si cambió dependencias) | — |
| SHIRO | `apps/api`, `packages/database`, `infra/compose.yml`, `infra/docker/api.Dockerfile`, `infra/scripts/` | — |

**Fuera de su zona ya detectado en `s2/shiro`:** `docs/evidence/g2/`, `docs/guia-inicio-local.md`, `package.json` (raíz) y
`.env.example`. No es grave si el contenido es correcto, pero ATLAS lo revisa línea a línea porque son archivos suyos.

### 3.2 Contratos intactos

```bash
git diff feat/semana-2...s2/moto  -- packages/shared   # debe salir vacío
git diff feat/semana-2...s2/shiro -- packages/shared   # debe salir vacío
```

### 3.3 Secretos y claves privadas: en todo el historial, no solo en el último commit

```bash
for b in s2/moto s2/shiro; do
  echo "== $b"
  git log -p feat/semana-2..$b | grep -nE 'BEGIN (EC |ENCRYPTED )?PRIVATE KEY|"d" *: *"|APP_DB_PASSWORD=.+|CSRF_SECRET=[0-9a-f]{32,}'
  git ls-tree -r --name-only $b | grep -E '(^|/)secrets/|\.pem$|\.key$|\.private\.jwk$'
done
```

Ambos comandos deben salir **vacíos**. Una clave privada que llegó a un commit cuenta como **comprometida** aunque luego
se haya borrado: hay que regenerarla y reescribir esa rama antes de fusionar.

**Cada coincidencia se mira a mano.** En la primera pasada (2026-10-26) salieron 4, todas falsos positivos:

| Rama | Coincidencia | Por qué no es un secreto |
| --- | --- | --- |
| `s2/moto` | `expect(pem).toMatch(/^-----BEGIN PRIVATE KEY-----/)` (2 veces) | Es una aserción de un test sobre una clave generada en memoria; no hay ninguna clave en el archivo |
| `s2/shiro` | `APP_DB_PASSWORD=replace-with-a-random-password…` en `.env.example` | Es un valor de ejemplo (`replace-with…`) |
| `s2/shiro` | `APP_DB_PASSWORD=` en la guía | Es una instrucción sin valor |

Ninguna de las dos ramas contiene archivos `secrets/`, `.pem`, `.key` ni `.private.jwk`.

### 3.4 Pruebas desactivadas o reglas silenciadas

```bash
for b in s2/moto s2/shiro; do
  echo "== $b"
  git diff feat/semana-2...$b | grep -nE '^\+.*(\.skip\(|\.only\(|\bxit\(|\bxdescribe\(|eslint-disable|@ts-ignore|@ts-expect-error|passWithNoTests|as any\b)'
done
```

Cada aparición debe tener una justificación clara en el código. Si no la tiene, es un hallazgo.

### 3.5 Atribución de los commits

```bash
git log --format='%h %s%n%b' feat/semana-2..s2/shiro | grep -c 'Co-Authored-By'
```

Cada commit lleva su línea `Co-Authored-By` con el modelo que **realmente** hizo el trabajo (SHIRO firma como
Sonnet 5.5, y es correcto).

---

## 4. Lectura del código crítico

No hace falta leer las 9500 líneas con la misma atención. Se lee **a fondo** lo que protege una propiedad de
seguridad y **en diagonal** lo demás (UI, documentación).

### 4.1 MOTO: firmante, CLI de confianza y verificación

| Área | Dónde mirar | Qué tiene que cumplirse | Señal de alarma |
| --- | --- | --- | --- |
| Firma | `apps/signer/src` | `dsaEncoding: 'ieee-p1363'`; usa **el mismo** `canonicalize` de `@alertasegura/verification`; `key_id` con `computeKid`; fechas normalizadas a UTC con segundos **antes** de canonicalizar | Una segunda implementación de JCS; firma en DER; `key_id` que viene del cliente |
| Validación de entrada | servidor del firmante | `SignRequestSchema` estricto; rechaza `MANIFIESTO` y cualquier `tipo_doc` desconocido; límite de 16 kB; JSON inválido → 400 | Firma «lo que llegue»; acepta campos extra |
| Clave privada | arranque del firmante | Se lee **una vez** de `SIGNER_PRIVATE_KEY_PATH`; se conserva como `KeyObject` y no como texto; nunca se registra en los logs | Imprimir la clave o el payload completo; releer la clave en cada petición |
| Socket | creación del servidor | En Linux, `chmod 0660` al crearlo; se borra un socket huérfano al arrancar | Puerto TCP abierto o permisos 0777 |
| Errores | respuestas del firmante | Solo el código y un mensaje genérico (`SignerErrorSchema`) | Trazas, rutas de archivos o detalles de OpenSSL en la respuesta |
| trust-cli | `tools/trust-cli/src` | Por defecto, la raíz en `~/.alertasegura-lab`, **fuera del repo**; versión del manifiesto estrictamente creciente; vigencia de 7 días como máximo; `revoke` y `rotate` emiten un manifiesto nuevo | Escribe la raíz en la carpeta del proyecto; permite repetir o bajar la versión |
| Verificación | `packages/verification/src` | `verifyDocument` en este orden: firma sobre los bytes → `hash_payload` → `key_id` (sobre, payload y JWK) → `tipo_doc` → esquema Zod. Rechaza una JWK con `d`. `verifyCancelacion` compara `hash_alerta` con el hash real de la alerta | Interpretar el JSON **antes** de verificar; comparar con `==` sin pasar por el esquema |
| Vectores | `tests/fixtures/crypto/p16-*.json`, `p06-*.json` | Solo claves públicas y firmas; generados con claves efímeras | Cualquier `"d":` en un fixture |
| Docker del firmante | `infra/docker/signer.Dockerfile` | `USER 10001`; sin `COPY` de claves; la clave llega montada en tiempo de ejecución | `COPY secrets` o clave dentro de la imagen |
| Web | `apps/web/src` | Formulario con el catálogo de `shared` (Bolivia); fechas en `America/La_Paz`; el CSRF sigue igual; nada privado en el bundle | Hora en UTC sin convertir; catálogos copiados a mano |

### 4.2 SHIRO: base de datos, roles SQL y API

| Área | Dónde mirar | Qué tiene que cumplirse | Señal de alarma |
| --- | --- | --- | --- |
| Migración del borrador (D-4) | `packages/database/prisma/migrations/*` | La conversión de datos coincide con la ficha (INFO→AMARILLA…); sin pérdida silenciosa; `CHECK` en `vigenciaHoras` 1–72 | `DROP COLUMN` antes de copiar los datos |
| Tablas inmutables | `schema.prisma` y migraciones | `payloadCanonico` en **bytea**; un borrador → una alerta (UNIQUE); una cancelación por alerta (UNIQUE); FKs con `RESTRICT` | `payload` guardado como JSON o texto |
| Rol SQL (P07) | script de `db:roles` | Idempotente; contraseña tomada solo de `APP_DB_PASSWORD`; permisos **exactos** del contrato; `ALTER DEFAULT PRIVILEGES`; sin `TRUNCATE` | `GRANT ALL`; la contraseña escrita en SQL versionado |
| D-1 | `packages/database/lab`, `apps/api/src/modules/users` | `POST /admin/issuers` → 404; el script pide la contraseña por stdin o variable de entorno, **nunca por argumento**; audita `ISSUER_PROVISIONED` con `lab-script` | Contraseña en `argv`, que queda en el historial |
| Publicación atómica | `apps/api/src/modules/alerts` | Firma **fuera** de la transacción; la transacción incluye alerta + estado + borrador + auditoría; firmante caído → 503 **sin filas**; doble publicación → 409 | Firmar dentro de la transacción; auditar fuera de ella |
| Cancelación (P02c) | mismo módulo | La propiedad (`emisor_id`) se comprueba **antes** de firmar; ajena → 403 + `CANCEL_DENIED`; `hash_alerta` = `hash_payload` guardado | Firmar antes de autorizar |
| Estado firmado | servicio de estado | `expires_at` ≤ +600 s; regeneración solo con `INSERT`; VENCIDA tras `expira_en` | `UPDATE` del estado (el rol app no debería poder hacerlo) |
| Lecturas públicas | controladores `/alerts`, `/trust/manifest` | Solo GET; devuelven los sobres tal cual están guardados | Reconstruir el payload a partir de columnas |
| Cuota | guard + transacción | Cuenta las publicaciones reales; `pg_advisory_xact_lock` por emisor; 429 con `Retry-After` | Contador en memoria |
| Cliente del firmante | `apps/api/src/...signer...` | Timeout de 3 s; valida la respuesta con `SignResponseSchema`; no reintenta a ciegas | Aceptar cualquier respuesta |
| Docker | `infra/compose.yml`, `infra/docker/api.Dockerfile`, `infra/scripts/p15-api-isolation.sh` | API con `USER 10002`; clave montada **solo** en `signer`; socket en un volumen compartido; la API no tiene la ruta de la clave | La clave montada en `api`; contenedores con privilegios |
| Purga y CSP | `SessionPurgeService`, `app.setup.ts` | Borra solo caducadas, inactivas y revocadas hace más de 24 h; CSP `default-src 'none'` | Borrar sesiones vivas |
| Archivos de ATLAS | `docs/guia-inicio-local.md`, `package.json`, `.env.example` | Cambios mínimos y correctos | Valores reales en `.env.example` |

---

## 5. Pruebas dentro del worktree de cada agente

Se ejecutan **antes** de fusionar, en la copia del agente, para que un fallo no rompa la rama de integración.

```bash
# MOTO
cd .worktrees/moto
pnpm install --frozen-lockfile && pnpm build:packages
pnpm --filter @alertasegura/verification test          # P13 debe seguir 46/46 + P16 + P06
pnpm --filter @alertasegura/verification exec vitest run -t P13
pnpm --filter @alertasegura/signer test
pnpm --filter @alertasegura/trust-cli test
pnpm --filter @alertasegura/web test && pnpm --filter @alertasegura/web build
grep -rlE 'BEGIN (EC )?PRIVATE|"d":"' apps/web/dist || echo "bundle limpio"

# SHIRO
cd .worktrees/shiro
pnpm install --frozen-lockfile && pnpm build:packages
pnpm db:deploy && pnpm db:roles
pnpm --filter @alertasegura/api typecheck && pnpm --filter @alertasegura/api lint
pnpm --filter @alertasegura/api test                   # reportado: 63/63
pnpm --filter @alertasegura/api test:e2e               # reportado: 169/169
```

Hay que comparar el **número real** con el que reportó el agente. Si no coincide, se le pregunta por qué.

---

## 6. Hallazgos: cómo se clasifican y se devuelven

| Severidad | Significa | Qué pasa |
| --- | --- | --- |
| **ALTA** | Rompe un control de seguridad, una prueba G2 o el contrato; clave o secreto expuesto | **Bloquea la fusión.** El agente corrige en su rama |
| **MEDIA** | Funciona, pero con un riesgo o una desviación del plan | Se corrige antes de cerrar la semana, o se documenta como riesgo residual |
| **BAJA** | Estilo, nombres, documentación | Se anota y puede quedar para después |

Formato de cada hallazgo que ATLAS envía al agente por SendMessage:

```text
[ALTA] S2-21 · apps/api/src/modules/alerts/publish.service.ts:88
Qué: la auditoría ALERT_PUBLISHED se inserta fuera de la transacción.
Por qué importa: si la auditoría falla queda una alerta publicada sin registro (§08 exige ROLLBACK).
Cómo comprobarlo: e2e "fallo de auditoría → rollback" con el INSERT de auditoría forzado a fallar.
Esperado: mover el INSERT dentro de $transaction y añadir la prueba.
```

Después de la corrección, **se revisa solo lo que cambió** (`git diff <hash-revisado>..s2/<agente>`) y se repite la
sección 5.

---

## 7. Fusión en `feat/semana-2`

```bash
git switch feat/semana-2
git merge --no-ff s2/moto  -m "merge: entrega de MOTO (semana 2)"
pnpm install && pnpm build:packages && pnpm test            # comprobación rápida tras cada fusión
git merge --no-ff s2/shiro -m "merge: entrega de SHIRO (semana 2)"
```

- **Conflictos esperables:** en `pnpm-lock.yaml` no se edita a mano: se acepta una versión y se regenera con
  `pnpm install`. En `package.json` se juntan los scripts de los dos.
- **Pendientes de ATLAS al integrar** (pedidos por SHIRO):
  - Añadir `TRUST_MANIFEST_UNAVAILABLE` en `shared` (y avisar a SHIRO).
  - Crear `.gitattributes` (`*.sh` y `Dockerfile` con `eol=lf`).
  - Añadir el alias `pnpm lab`.
  - Completar el `.env` de la raíz (`DATABASE_MIGRATION_URL`, `APP_DB_PASSWORD`, `DATABASE_URL` con el rol app) y
    ejecutar `db:deploy` + `db:roles`.
  - Montar el manifiesto en el compose.
- **Tras la fusión:** se avisa a cada agente para que ejecute `git merge feat/semana-2` en su worktree.

---

## 8. Verificación integrada y aceptación del GATE G2

En la raíz, con todo fusionado:

```bash
pnpm build && pnpm typecheck && pnpm lint && pnpm test && pnpm test:e2e
pnpm test:g1                                           # regresión P01, P02a, P02b, P09 (con D-1)
docker compose -f infra/compose.yml --env-file .env --profile g2 up -d --build
```

| Prueba | Cómo la ejecuta ATLAS (independiente del agente) | Evidencia |
| --- | --- | --- |
| P02c | Caja negra: el emisor B cancela una alerta del A → 403; consultar la auditoría `CANCEL_DENIED` | `docs/evidence/g2/P02c.json` |
| P03 API | `GET /alerts/:id`, alterar mensaje, fecha y severidad, verificar con `verifyDocument` → rechazo; comprobar en la BD que los bytes no cambiaron | `P03.json` |
| P06 backend | Cancelar → estado CANCELADA verificable; eventos falsificados → `verifyCancelacion` los rechaza; el historial aparece en `GET /alerts/:id` | `P06.json` |
| P07 | `psql` como `alertasegura_app`: UPDATE, DELETE y TRUNCATE en las 4 tablas → 42501 | `P07.txt` (salida real) |
| P15 | `docker compose exec api node -e "fs.readFileSync(...)"` → EACCES o ENOENT, y explicar cuál y por qué | `P15.txt` |
| P16 | Intercambiar firmas ALERTA ↔ EVENTO sobre datos **reales** de la API (no solo vectores) | `P16.json` |
| Regresión G1 | P01, P02a, P02b, P09 y P13 | logs |

Al final:
- Revisión de seguridad del diff completo de la semana.
- Escaneo de secretos de la rama de integración.
- `docs/evidence/semana2-cumplimiento.md`.
- Matriz T1–T11 actualizada.

---

## 9. Registro de la revisión

ATLAS deja constancia en `docs/coordination/revision-semana2-registro.md`:

| Rama | Commit revisado | Controles automáticos | Pruebas (real / reportado) | Hallazgos A / M / B | Decisión |
| --- | --- | --- | --- | --- | --- |
| `s2/moto` | `5703a18` | … | … | … | Fusionado / Devuelto |
| `s2/shiro` | `b6bf73c` | … | … | … | Fusionado / Devuelto |

---

## 10. Revisión rápida para el autor (unos 15 minutos)

Si quieres comprobarlo tú mismo, sin leer todo el código:

1. **Que no hay claves privadas:** ejecuta el bloque de la sección 3.3. Debe salir vacío.
2. **Que las pruebas pasan:** ejecuta la sección 5 en cada worktree y compara los números con los que reportaron.
3. **Que la publicación es inmutable (P07):** en DBeaver, conéctate con el usuario `alertasegura_app` y ejecuta
   `UPDATE "AlertaPublicada" SET "keyId" = 'x';`. Debe fallar con *permission denied*.
4. **Que la firma protege el contenido:** publica una alerta desde la web, ábrela en `GET /api/v1/alerts/<id>` y
   compárala con lo que ves. La semana 3 añadirá la verificación visual en la PWA.
5. **Que el emisor B no puede cancelar alertas de A (P02c):** inicia sesión con `emisor2` e intenta cancelar una alerta
   de `emisor1`. Debe responder 403.
