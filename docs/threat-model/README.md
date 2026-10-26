# Modelo de amenazas

Referencia oficial: `AlertaSegura_Propuesta_Definitiva_Seguridad_4_Semanas.pdf`, secciones 02 (adversarios),
03 (actores y permisos), 09 (amenazas, controles y evidencia) y 13 (riesgos residuales). Este documento reproduce
esa matriz sin cambiar sus amenazas, riesgos, controles ni pruebas, y añade el estado real al cierre de cada semana (S1 y S2).

## Activos

| Activo | Por qué importa |
| --- | --- |
| Clave privada del servicio firmante | Quien la controla produce firmas matemáticamente válidas sobre alertas falsas |
| Clave raíz de prueba y manifiesto de confianza | Deciden qué claves acepta la PWA y cuáles están revocadas |
| Cuentas de emisor y de administrador | Permiten crear, publicar y cancelar alertas o gestionar usuarios |
| Sesiones activas | Equivalen a la cuenta mientras están vigentes |
| Alertas publicadas, eventos de cancelación y estado firmado | Su integridad y frescura determinan lo que el ciudadano cree vigente |
| Registro de auditoría | Atribuye las acciones críticas (la firma prueba origen del sistema, no autoría individual) |

## Actores (sección 03)

| Actor | Función | Restricción de seguridad |
| --- | --- | --- |
| Administrador | Gestionar usuarios ordinarios y consultar auditoría | No publica alertas ni se autoasigna rol emisor; altas de emisores mediante script del responsable de laboratorio |
| Emisor A o B | Iniciar sesión, crear borradores, publicar y cancelar sus propias alertas | Verificación por rol y por `emisor_id`; no accede a claves privadas |
| Ciudadano | Consultar listado, detalle y evidencia local sin iniciar sesión | No posee endpoints de escritura públicos |
| Servicio firmante | Firmar payloads validados desde un canal interno restringido | Proceso y usuario de sistema independientes; único con acceso a la clave privada |
| Responsable del laboratorio | Emitir y actualizar el manifiesto y revocar claves con utilidad offline | Clave raíz fuera del servicio web y del repositorio |

## Adversarios (sección 02)

**Dentro del alcance:** público anónimo; rol autenticado sin permiso; emisor sobre alerta ajena; proxy que altera u
oculta datos; cuenta SQL de la aplicación; robo simulado de clave.
**Fuera del alcance:** superusuario de BD; web comprometida que reemplaza la PWA; dispositivo o reloj malicioso.

## Matriz T1–T11 (sección 09)

Estados:
- **Mitigado:** control implementado y prueba oficial aprobada.
- **Parcial:** parte del control implementada y probada; la prueba oficial que falta es de un gate posterior.
- **Pendiente:** se aborda en el gate indicado.

Los estados se actualizan al cierre de cada semana, con su evidencia.

| ID | Amenaza | Riesgo | Control propuesto | Prueba | Gate | Estado tras S1 | Estado tras S2 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T1 | Publicación anónima / sin rol | **ALTO** | Sesión, RBAC, 401/403 y alta controlada de emisores | P01, P02a–b | G1 | Mitigado | **Mitigado**. Regresión aprobada y alta de emisores por comando de laboratorio (D-1) |
| T2 | Modificación API/BD | **ALTO** | Firma de bytes canónicos, verificación local y SQL de mínimo privilegio | P03, P07, P11 | G2/G3 | Parcial | **Parcial**. P03 (API) y P07 aprobadas: alterar mensaje, fecha, severidad o departamento invalida la firma; el rol app no puede UPDATE/DELETE/TRUNCATE. Falta P11 (proxy con CA de laboratorio, S3) |
| T3 | Firma con clave robada | **ALTO** | Manifiesto de raíz; revocación completa y control de versión | P04, P14 | G3/G4 | Pendiente | **Parcial**. CLI offline con raíz fuera del repositorio, manifiesto firmado de versión creciente, `revoke` y `rotate`, y clave aislada (P15). Faltan P04 (PWA, S3) y P14 (S4) |
| T4 | Alerta caducada | MEDIO | `expira_en` firmado + reloj evaluado localmente (limitado por su confianza) | P05 | G3 | Pendiente | **Parcial**. `expira_en` va firmado y el estado firmado pasa a VENCIDA. Falta P05 en la PWA (S3) |
| T5 | Cancelación falsa | **ALTO** | Evento firmado con `hash_alerta` | P06 | G2/G3 | Pendiente | **Parcial**. P06 backend aprobada: se rechazan un evento de otra alerta, un `hash_alerta` alterado y una clave ajena. Falta P06 en la PWA (S3) |
| T6 | Escritura en publicado | **ALTO** | Tablas separadas y permisos sin UPDATE/DELETE | P07 | G2 | Pendiente | **Mitigado**. P07 aprobada: 15 sentencias denegadas con 42501 y la API no expone PUT/PATCH/DELETE |
| T7 | Auditoría modificada | MEDIO | HMAC encadenado + checkpoint fuera de BD; permisos append-only | P08/P08b | G3 | Parcial | **Parcial**. Ahora también lo protege el rol SQL (P07 sobre `AuditLog`). HMAC y checkpoint en S3 |
| T8 | Fuerza bruta / abuso | MEDIO | Rate limit por IP y usuario, y cuotas de publicación | P09 | G1 | Mitigado | **Mitigado**. P09 en regresión; cuota de publicación por emisor con bloqueo transaccional (S2-26) |
| T9 | Datos obsoletos en PWA | MEDIO | Cachear solo el shell; falta de frescura ⇒ NO COMPROBABLE | P10 | G3 | Pendiente | Pendiente (S3) |
| T10 | Emisor afecta alerta ajena | **ALTO** | Control de propiedad `emisor_id` en la API | P02c | G2 | Parcial | **Mitigado**. P02c aprobada: el emisor B recibe 403 y se audita `CANCEL_DENIED`; la alerta sigue VIGENTE |
| T11 | Supresión de cancelación | **ALTO** | Estado firmado fresco (10 min); rechazo sin estado válido | P06b | G3 | Pendiente | **Parcial**. ESTADO firmado con secuencia, `ultimo_evento_hash` y frescura ≤ 600 s (verificado en P06). Falta P06b (S3) |

## Amenazas altas → control → prueba (OE1)

OE1 exige, al cierre de S1, que el 100 % de las amenazas altas tenga un control y una prueba asignados.
Las siete amenazas ALTAS (T1, T2, T3, T5, T6, T10 y T11) los tienen en la matriz. Ejecutadas hasta ahora:

| Amenaza alta | Control verificado | Evidencia |
| --- | --- | --- |
| T1 | Anónimo → 401; ADMIN y AUDITOR → 403; emisores solo por alta de laboratorio | P01, P02a, P02b ([S1](../evidence/g1/), [regresión S2](../evidence/g2/regresion-g1/)) |
| T2 | Bytes JCS firmados y guardados tal cual; alteraciones rechazadas; rol SQL mínimo | P13, [P03](../evidence/g2/P03.json), [P07](../evidence/g2/P07.json) |
| T3 | Raíz offline, manifiesto firmado y clave del firmante inaccesible para la API | [P15](../evidence/g2/P15.json); P04 y P14 en S3–S4 |
| T5 | Evento firmado vinculado por `hash_alerta`; falsificaciones rechazadas | [P06](../evidence/g2/P06.json) (backend) |
| T6 | Sin UPDATE/DELETE/TRUNCATE para el rol app | [P07](../evidence/g2/P07.json) |
| T10 | El emisor B no cancela alertas del emisor A | [P02c](../evidence/g2/P02c.json) |
| T11 | Estado firmado fresco y encadenado | [P06](../evidence/g2/P06.json); P06b en S3 |

## Riesgos residuales (sección 13) y de implementación

- La firma ECDSA demuestra origen en el **sistema** y ausencia de alteraciones; no identifica a la persona. La atribución individual procede de sesión, RBAC y auditoría.
- Una clave robada produce firmas válidas hasta que el receptor recibe un manifiesto nuevo; la ventana se medirá en P14.
- La supresión de una cancelación puede sostener un estado viejo pero firmado mientras dure su frescura (máx. 10 min).
- Fuera de cobertura: servidor que sirve una PWA maliciosa, dispositivo comprometido, superusuario de BD y reloj del cliente alterado.
- HMAC encadenado y checkpoint externo detectan modificaciones bajo amenazas delimitadas; no sustituyen un almacenamiento inviolable ni un HSM.

Riesgos de la implementación:

| ID | Riesgo | Estado tras S2 |
| --- | --- | --- |
| R-01 | El firmante aislado no existía (T2, T3) | **Resuelto**: firmante en su propio contenedor (usuario 10001), socket 0660 y clave inaccesible para la API (P15) |
| R-02 | Sin TLS de laboratorio (RNF01) | **Mitigado en código**: TLS con mkcert en Vite y cookies `Secure`/`__Host-` probadas en e2e; demostración con certificado pendiente |
| R-03 | Rate limiting en memoria de un solo proceso | Abierto (la cuota de publicación sí se cuenta en la BD) |
| R-04 | El límite por cuenta permite bloquear temporalmente una cuenta conocida | Abierto |
| R-05 | La API usaba el rol propietario de PostgreSQL | **Resuelto**: rol `alertasegura_app` (P07) |
| R-06 | Un manifiesto con `issued_at` futuro no se rechaza en `verifyManifest` (hallazgo H-1) | Abierto, para la verificación en la PWA (S3) |
| R-07 | En Windows, los bind mounts no conservan dueño ni permisos 0400 de la clave | El aislamiento real se demuestra en Linux con un volumen (P15 B/C); en el laboratorio la clave solo se monta en `signer` |
