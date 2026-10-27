# Registro de revisión — Semana 2

Revisión de ATLAS según [`revision-semana2.md`](revision-semana2.md). Las pruebas las **ejecutó ATLAS** en el worktree
de cada agente, antes de fusionar. Fecha: 2026-10-26.

## Resumen

| Rama | Commit revisado | Controles automáticos | Pruebas (ATLAS / reportado) | Hallazgos A / M / B | Decisión |
| --- | --- | --- | --- | --- | --- |
| `s2/moto` | `5703a18` | Propiedad ✅ · contratos intactos ✅ · secretos: 2 falsos positivos ✅ · sin pruebas desactivadas ✅ | verification 162/162 (P13 46/46) · signer 20/20 (+2 solo Linux) · trust-cli 23/23 · web 74/74 / coinciden | 0 / 0 / 1 | **Fusionado** (`6efbe79`) |
| `s2/shiro` | `b6bf73c` | Propiedad: toca `docs/`, `package.json` y `.env.example` (aceptado tras leerlo línea a línea) · contratos intactos ✅ · secretos: 2 falsos positivos ✅ · sin pruebas desactivadas ✅ | typecheck y lint ✅ · unitarias 63/63 · e2e 169/169 / coinciden | 0 / 0 / 0 | **Fusionado** (`9e167bf`) |
| `s2/shiro` (entrega 6) | `ace3d7b` | Cambio de 3 archivos | e2e `s2-24` 12/12 | 0 / 0 / 0 | **Fusionado** (`455ec48`) |

**Rama integrada `feat/semana-2`** (tras las tres fusiones): `pnpm build`, `typecheck`, `lint` ✅ · unitarias
**342/342** (api 63, verification 162, signer 20, trust-cli 23, web 74) · e2e **169/169**.

## Hallazgos

| # | Severidad | Rama | Dónde | Hallazgo | Resolución |
| --- | --- | --- | --- | --- | --- |
| H-1 | BAJA | `s2/moto` | `packages/verification/src/documents.ts` (`verifyManifest`) | No rechaza un manifiesto con `issued_at` posterior a `ahora` | Para la semana 3 (verificador PWA, P04/P14) |

## Aspectos revisados a fondo

**MOTO**
- **Firmante:** valida con `SignRequestSchema` estricto y exige fechas ya normalizadas. Añade él mismo el `key_id`,
  rechaza `MANIFIESTO`, cuerpos de más de 16 kB y JSON inválido. Lee la clave una vez y nunca la registra en los logs.
  El socket se crea con umask 0117 y luego 0660, y solo borra un socket huérfano, nunca un archivo normal.
- **`verifyDocument`:** sigue el orden sobre → `key_id` de la JWK → hash → firma → JSON UTF-8 → forma canónica JCS →
  `tipo_doc` → esquema → `key_id` del payload. No interpreta nada antes de verificar.
- **trust-cli:** `assertOutsideRepo` impide guardar la raíz dentro de un repositorio y `writeNewFile` usa la bandera
  `wx`, así que nunca sobrescribe. La versión del manifiesto es estrictamente creciente y una clave revocada no puede
  volver a ser la activa.
- **Dockerfile del firmante:** usuario 10001, imagen sin `node_modules` y ninguna clave dentro de la imagen.

**SHIRO**
- **Publicación atómica:** firma fuera de la transacción. Dentro, en una sola transacción: cuota bajo
  `pg_advisory_xact_lock`, alerta, estado, borrador (`updateMany` condicionado a DRAFT) y auditoría. La carrera de dos
  publicaciones del mismo borrador termina en 409.
- **`SigningService`:** comprueba que lo firmado es exactamente lo pedido (`isDeepStrictEqual`) y que el hash corresponde
  a los bytes.
- **`APP_ROLE_POLICY`:** falla si aparece una tabla sin declarar, y los privilegios por defecto son solo
  `SELECT, INSERT`.
- **Comando `issuer:add`:** rechaza la contraseña por argumento.
- **Compose:** la clave se monta solo en `signer`. La API corre como 10002 y llega al socket mediante el grupo 10001.
