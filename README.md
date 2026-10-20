# AlertaSegura

Monorepo con React + Vite para la PWA, NestJS para la API, PostgreSQL con Prisma y un proceso aislado para la firma digital.

## Requisitos

| Herramienta | Versión | Comprobar |
| --- | --- | --- |
| Git | cualquiera reciente | `git --version` |
| Node.js | 24.11 o superior | `node -v` |
| pnpm | 12 (se activa con Corepack, incluido en Node) | `pnpm -v` |
| Docker Desktop | con Docker Compose, **abierto y en marcha** | `docker ps` (no debe dar error) |
| Google Chrome | solo para `pnpm test:browser` (opcional) | — |

## Levantar todo en local desde cero

Los comandos funcionan igual en PowerShell, Git Bash o una terminal de macOS/Linux, salvo donde se indica.

### 1. Clonar e instalar dependencias

```bash
git clone https://github.com/JHAMILCALI/notificaciones-de-alerta-segura.git alertasegura
cd alertasegura
git switch feat/semana-1          # mientras la semana 1 no esté fusionada en main
corepack enable                   # activa pnpm 12 (solo la primera vez; en Windows puede pedir terminal de administrador)
pnpm install
```

### 2. Crear el archivo `.env`

```bash
cp .env.example .env              # PowerShell: Copy-Item .env.example .env
```

`.env` está ignorado por Git: nunca lo subas. Ábrelo y cambia estos valores:

| Variable | Qué poner |
| --- | --- |
| `POSTGRES_PASSWORD` | Una contraseña cualquiera para la base local. **Repítela** dentro de `DATABASE_URL` (`postgresql://alertasegura:<contraseña>@localhost:5432/alertasegura`). |
| `CSRF_SECRET` | Un secreto aleatorio. Genéralo con `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. La API no arranca con el valor de ejemplo. |
| `SEED_ADMIN_PASSWORD`, `SEED_AUDITOR_PASSWORD`, `SEED_ISSUER1_PASSWORD`, `SEED_ISSUER2_PASSWORD` | Las contraseñas con las que vas a iniciar sesión, de **al menos 12 caracteres**. Si dejas una vacía, ese usuario no se crea. |

Si el puerto 5432 ya está ocupado (por ejemplo, por un PostgreSQL instalado en Windows), usa otro (p. ej. `5433`)
en `POSTGRES_PORT` **y** en el puerto de `DATABASE_URL`. El resto de variables pueden quedarse con su valor de ejemplo.

### 3. Compilar los paquetes compartidos

```bash
pnpm build:packages               # shared, database (incluye el cliente Prisma) y verification
```

### 4. Base de datos

```bash
pnpm db:up                        # arranca PostgreSQL 17 en Docker y espera a que esté listo
pnpm db:deploy                    # aplica las migraciones
pnpm db:seed                      # crea el administrador, el auditor y los dos emisores con las contraseñas del .env
```

El seed muestra una línea por usuario (`creado`, `ya existe` u `omitido` si falta su contraseña).

### 5. Arrancar la API y la web

```bash
pnpm dev
```

Arranca a la vez la API en `http://localhost:3000/api/v1` y la web en **`http://localhost:5173`**. Déjalo abierto:
se detiene con `Ctrl+C`. Comprobación rápida: `http://localhost:3000/api/v1/health` debe responder
`{"status":"ok","database":"up"}`.

### Iniciar sesión

1. Abre **`http://localhost:5173/login`** (o pulsa **Ingresar** en la barra superior).
2. Escribe el **correo** y la **contraseña** de uno de los usuarios del seed: las que pusiste en el `.env`.
3. Pulsa **Ingresar**. Llegas a **`/panel`**, que muestra tu nombre, rol, permisos y las secciones a las que puedes entrar.
4. Para salir, pulsa **Salir** en la barra superior.

| Usuario (correo por defecto) | Contraseña | Rol | Qué puede hacer en la semana 1 |
| --- | --- | --- | --- |
| `admin@alertasegura.local` | `SEED_ADMIN_PASSWORD` | Administrador | Ver usuarios y la auditoría. **No** publica alertas. |
| `auditor@alertasegura.local` | `SEED_AUDITOR_PASSWORD` | Auditor | Solo consultar la auditoría |
| `emisor1@alertasegura.local` | `SEED_ISSUER1_PASSWORD` | Emisor | Crear y ver **sus** borradores |
| `emisor2@alertasegura.local` | `SEED_ISSUER2_PASSWORD` | Emisor | Crear y ver **sus** borradores |

Sin iniciar sesión (ciudadano) puedes abrir el inicio (`/`) y el laboratorio criptográfico (`/laboratorio/criptografia`),
que verifica firmas de prueba en tu navegador. La publicación firmada de alertas llega en la semana 2: el botón de
publicar responde «no implementado» a propósito.

**Límites de seguridad que verás al probar:**

- Correo o contraseña incorrectos muestran siempre el mismo mensaje, para no revelar qué cuentas existen.
- Tras **5 intentos fallidos** en una misma cuenta, esa cuenta queda bloqueada **15 minutos** (respuesta 429). Desde un
  mismo equipo se admiten 10 intentos de login por minuto.
- La sesión caduca tras **30 minutos sin actividad** o 8 horas en total: vuelve a iniciar sesión.

### Problemas frecuentes

| Síntoma | Solución |
| --- | --- |
| `pnpm db:up` falla con «failed to connect to the docker API» | Abre Docker Desktop y espera a que diga *Engine running* |
| PostgreSQL no arranca: puerto 5432 en uso | Cambia `POSTGRES_PORT` y el puerto de `DATABASE_URL` (paso 2) |
| La API se cierra al arrancar con un error de configuración | Revisa el `.env`: `CSRF_SECRET` sigue con el valor de ejemplo o falta una variable |
| `Cannot find module '@alertasegura/...'` o falta el cliente Prisma | Ejecuta `pnpm build:packages` (paso 3) |
| El login dice que el correo o la contraseña son incorrectos | Usa exactamente la contraseña del `.env`. El seed **no cambia** la contraseña de un usuario que ya existe |
| «Demasiados intentos» | Espera el tiempo indicado (hasta 15 min por cuenta) o reinicia la API |
| `Port 5173 is already in use` | Ya hay otra web de Vite abierta: ciérrala o usa la que está en marcha |

### Apagar

`Ctrl+C` en la terminal de `pnpm dev`, y `pnpm db:down` para parar PostgreSQL (los datos se conservan para la próxima vez).

### Otras variables

- `COOKIE_SECURE=true` es obligatorio detrás de HTTPS: activa `Secure` y el prefijo `__Host-` en las cookies.
- `RATE_*` y `SESSION_*` ajustan los límites y caducidades (valores por defecto en `docs/coordination/api-contract.md`).

## Verificación

```bash
pnpm typecheck              # todo el monorepo
pnpm build
pnpm test                   # unitarias: api (Jest), web y verification (Vitest)
pnpm test:e2e               # API contra PostgreSQL real (crea y borra su propia base)
pnpm --filter @alertasegura/verification vectors   # regenera los vectores P13 con una clave efímera
pnpm test:g1                # aceptación G1 de caja negra contra la API en marcha
pnpm test:browser           # complementaria: recorrido en Google Chrome real (requiere Chrome instalado y pnpm dev)
pnpm test:cleanup           # simulación de limpieza de borradores de prueba; `pnpm test:cleanup -- --apply` los borra
```

Resultados y evidencias de la semana 1: [`docs/evidence/semana1-cumplimiento.md`](docs/evidence/semana1-cumplimiento.md).

## Proyectos

- `apps/web`: interfaz React, rutas y funciones PWA. Es el único frontend (`apps/frontend` no se usa).
- `apps/api`: API NestJS, autenticación, permisos, alertas y auditoría.
- `apps/signer`: proceso aislado que será el único consumidor de la clave privada.
- `packages/database`: esquema, migraciones y semilla de Prisma.
- `packages/shared`: contratos de datos compartidos (Zod), en ESM y CommonJS.
- `packages/verification`: canonicalización JCS (RFC 8785) y verificación ECDSA P-256 con Web Crypto.
- `tools/trust-cli`: administración de claves, manifiestos y revocación.

## Módulos de seguridad

| Módulo | Implementación | Estado semana 1 |
| --- | --- | --- |
| M1. Identidad y acceso | `apps/api/src/modules/auth`, `users`, `common/guards` | Implementado: Argon2id, sesiones, CSRF, RBAC, propiedad, rate limiting |
| M2. Ciclo de vida | `apps/api/src/modules/drafts` y `alerts` | Borradores mínimos y autorización de publicación (501 hasta la firma) |
| M3. Firma y claves | `apps/api/src/modules/trust`, `apps/signer` y `tools/trust-cli` | Semana 2 |
| M4. Verificador PWA | `apps/web/src/features/verification` y `packages/verification` | JCS + verificación Web Crypto y laboratorio; PWA final en semanas posteriores |
| M5. Auditoría | `apps/api/src/modules/audit` | Implementado: registro append-only con trigger |

La API y la PWA no deben leer la clave privada. El firmante se ejecutará con usuario, red y montaje de secreto separados; la PWA solo recibirá material público para verificar firmas mediante Web Crypto.

## Documentación

[Arquitectura](docs/architecture/README.md) · [Base de datos](docs/database/README.md) · [Modelo de amenazas](docs/threat-model/README.md) · [Contrato API](docs/coordination/api-contract.md) · [Coordinación](docs/coordination/README.md)
