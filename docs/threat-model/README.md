# Modelo de amenazas

Referencia oficial: `AlertaSegura_Propuesta_Definitiva_Seguridad_4_Semanas.pdf`, secciones 02 (adversarios),
03 (actores y permisos), 09 (amenazas, controles y evidencia) y 13 (riesgos residuales). Este documento reproduce
esa matriz sin cambiar sus amenazas, riesgos, controles ni pruebas, y añade el estado real tras la semana 1.

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

Estado tras la semana 1: **Mitigado** (control implementado y prueba oficial aprobada), **Parcial** (parte del
control implementada y probada; la prueba oficial corresponde a un gate posterior) o **Pendiente** (gate indicado).

| ID | Amenaza | Riesgo | Control propuesto | Prueba | Gate | Estado tras S1 |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | Publicación anónima / sin rol | **ALTO** | Sesión, RBAC, 401/403 y alta controlada de emisores | P01, P02a–b | G1 | **Mitigado**: P01, P02a y P02b aprobadas |
| T2 | Modificación API/BD | **ALTO** | Firma de bytes canónicos, verificación local y SQL de mínimo privilegio | P03, P07, P11 | G2/G3 | **Parcial**: JCS y verificación Web Crypto listas (P13); firma de publicaciones y rol SQL mínimo en S2 |
| T3 | Firma con clave robada | **ALTO** | Manifiesto de raíz; revocación completa y control de versión | P04, P14 | G3/G4 | Pendiente |
| T4 | Alerta caducada | MEDIO | `expira_en` firmado + reloj evaluado localmente (limitado por su confianza) | P05 | G3 | Pendiente |
| T5 | Cancelación falsa | **ALTO** | Evento firmado con `hash_alerta` | P06 | G2/G3 | Pendiente |
| T6 | Escritura en publicado | **ALTO** | Tablas separadas y permisos sin UPDATE/DELETE | P07 | G2 | Pendiente (aún no existe `ALERTA_PUBLICADA`) |
| T7 | Auditoría modificada | MEDIO | HMAC encadenado + checkpoint fuera de BD; permisos append-only | P08/P08b | G3 | **Parcial**: trigger append-only (UPDATE/DELETE/TRUNCATE rechazados, probado en e2e); HMAC y checkpoint en S3 |
| T8 | Fuerza bruta / abuso | MEDIO | Rate limit por IP y usuario, y cuotas de publicación | P09 | G1 | **Mitigado** en login y API: P09 aprobada; las cuotas de publicación llegan con la publicación (S2) |
| T9 | Datos obsoletos en PWA | MEDIO | Cachear solo el shell; falta de frescura ⇒ NO COMPROBABLE | P10 | G3 | Pendiente |
| T10 | Emisor afecta alerta ajena | **ALTO** | Control de propiedad `emisor_id` en la API | P02c | G2 | **Parcial**: propiedad implementada y probada sobre borradores (emisor B → 403 en P02b); P02c sobre alertas en S2 |
| T11 | Supresión de cancelación | **ALTO** | Estado firmado fresco (10 min); rechazo sin estado válido | P06b | G3 | Pendiente |

## Amenazas altas → control → prueba (OE1)

OE1 exige, al cierre de S1, que el 100 % de las amenazas altas tenga un control y una prueba asignados.
Las siete amenazas ALTAS (T1, T2, T3, T5, T6, T10 y T11) los tienen en la matriz. Ejecutadas hasta ahora:

| Amenaza alta | Control verificable en S1 | Evidencia |
| --- | --- | --- |
| T1 | Anónimo → 401; ADMIN/AUDITOR → 403; emisores solo por alta controlada | P01, P02a, P02b ([`docs/evidence/g1/`](../evidence/g1/)) |
| T2 | Bytes JCS idénticos en Node y Web Crypto; contenido alterado rechazado | P13 (base criptográfica de P03/P11) |
| T10 | Emisor B no lee ni publica el borrador del emisor A (403) | P02b (precursor de P02c) |
| T3, T5, T6, T11 | Diseñados; dependen del firmante, la publicación y el manifiesto | Gates G2–G4 |

## Riesgos residuales (sección 13) y de implementación

- La firma ECDSA demuestra origen en el **sistema** y ausencia de alteraciones; no identifica a la persona. La atribución individual procede de sesión, RBAC y auditoría.
- Una clave robada produce firmas válidas hasta que el receptor recibe un manifiesto nuevo; la ventana se medirá en P14.
- La supresión de una cancelación puede sostener un estado viejo pero firmado mientras dure su frescura (máx. 10 min).
- Fuera de cobertura: servidor que sirve una PWA maliciosa, dispositivo comprometido, superusuario de BD y reloj del cliente alterado.
- HMAC encadenado y checkpoint externo detectan modificaciones bajo amenazas delimitadas; no sustituyen un almacenamiento inviolable ni un HSM.

Riesgos de la implementación de la semana 1:

| ID | Riesgo | Plan |
| --- | --- | --- |
| R-01 | El firmante aislado no existe todavía (T2, T3) | Semana 2 (D6) |
| R-02 | Sin TLS de laboratorio: `Secure`/`__Host-` solo con `COOKIE_SECURE=true` (RNF01) | TLS de laboratorio antes de la demostración |
| R-03 | Rate limiting en memoria de un solo proceso | Almacén compartido si se escala |
| R-04 | El límite por cuenta permite bloquear temporalmente una cuenta conocida | Límite por cuenta+IP o CAPTCHA |
| R-05 | La API usa el rol propietario de PostgreSQL | Rol app sin UPDATE/DELETE en publicaciones y auditoría (P07, semana 2) |
