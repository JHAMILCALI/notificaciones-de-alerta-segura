# Guía de inicio local — AlertaSegura

Paso a paso para inicializar el proyecto completo en tu equipo, en el orden correcto, comprobando cada pieza
antes de pasar a la siguiente.

## Qué se levanta y en qué orden

Cada pieza depende de la anterior. Si una falla, las siguientes no funcionan:

```text
 1. Docker Desktop          el motor que ejecuta la base de datos
        │
 2. PostgreSQL (contenedor)  la base de datos, dentro de Docker            puerto 5432 (o el de POSTGRES_PORT)
        │
 3. Migraciones              crean las tablas en la base vacía
        │
 4. Seed                     crea los usuarios para iniciar sesión
        │
 5. API NestJS               lee y escribe en la base                       http://localhost:3000/api/v1
        │
 6. Web React (Vite)         la interfaz; envía todo /api a la API          http://localhost:5173
        │
 7. Navegador                inicias sesión
```

Antes de todo eso, **solo la primera vez**, hay que preparar el proyecto: dependencias, `.env` y compilación de los
paquetes compartidos (pasos 0.1 a 0.4).

---

## Primera vez (desde cero)

### 0.1. Comprueba las herramientas

| Herramienta | Comando | Debe mostrar |
| --- | --- | --- |
| Git | `git --version` | cualquier versión |
| Node.js | `node -v` | `v24.11` o superior |
| Docker | `docker --version` | cualquier versión con Compose |

### 0.2. Clona e instala

```bash
git clone https://github.com/JHAMILCALI/notificaciones-de-alerta-segura.git alertasegura
cd alertasegura
git switch feat/semana-1        # mientras la semana 1 no esté fusionada en main
corepack enable                 # activa pnpm 12; en Windows puede pedir una terminal de administrador
pnpm install
```

✅ Comprobación: `pnpm -v` muestra `12.x` y `pnpm install` termina con `Done`.

### 0.3. Crea el `.env`

```bash
cp .env.example .env            # PowerShell: Copy-Item .env.example .env
```

Abre `.env` y cambia **solo** esto:

1. `POSTGRES_PASSWORD=` → una contraseña para la base local, por ejemplo `local-pg-2026`.
2. `DATABASE_URL=` → pon **la misma** contraseña:
   `postgresql://alertasegura:local-pg-2026@localhost:5432/alertasegura`
3. `CSRF_SECRET=` → pega el resultado de:
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```
4. `SEED_ADMIN_PASSWORD=`, `SEED_AUDITOR_PASSWORD=`, `SEED_ISSUER1_PASSWORD=`, `SEED_ISSUER2_PASSWORD=` → las contraseñas
   con las que vas a entrar, **de 12 caracteres o más**. Anótalas.

> **¿Tienes PostgreSQL instalado en Windows?** Ocupa el puerto 5432. Usa otro, por ejemplo 5433, en `POSTGRES_PORT=5433`
> **y** en `DATABASE_URL` (`...@localhost:5433/...`). Para comprobar si está libre en PowerShell:
> `Get-NetTCPConnection -LocalPort 5432 -State Listen` (si no muestra nada, está libre).

El `.env` nunca se sube a Git (está en `.gitignore`).

### 0.4. Compila los paquetes compartidos

```bash
pnpm build:packages
```

Compila `shared` (contratos), `database` (genera el cliente Prisma) y `verification` (criptografía). La API y la web
los importan ya compilados, por eso va antes de arrancarlas.

✅ Comprobación: termina sin errores (`Done` en los tres paquetes).

---

### 1. Abre Docker Desktop

Ábrelo desde el menú de inicio y espera a que indique **Engine running**.

✅ Comprobación: `docker ps` muestra una tabla (aunque esté vacía) y **no** el error `failed to connect to the docker API`.

### 2. Levanta PostgreSQL

```bash
pnpm db:up
```

Crea y arranca el contenedor `infra-postgres-1` y espera a que esté sano.

✅ Comprobación: el comando termina con `Container infra-postgres-1 Healthy`. También con `docker ps`:
debe aparecer `infra-postgres-1` con estado `(healthy)`.

### 3. Aplica las migraciones

```bash
pnpm db:deploy
```

Crea las tablas (`User`, `Session`, `Draft`, `AuditLog`) y los triggers que impiden modificar la auditoría.

✅ Comprobación: muestra `2 migrations found` y `applied` la primera vez (o `No pending migrations to apply` si ya estaban).

### 4. Crea los usuarios (seed)

```bash
pnpm db:seed
```

✅ Comprobación: una línea por usuario:

```text
[seed] ADMIN: creado (admin@alertasegura.local).
[seed] AUDITOR: creado (auditor@alertasegura.local).
[seed] ISSUER 1: creado (emisor1@alertasegura.local).
[seed] ISSUER 2: creado (emisor2@alertasegura.local).
```

Si aparece `omitido`, falta esa contraseña en el `.env` o tiene menos de 12 caracteres: corrígela y repite este paso.
El seed se puede repetir sin riesgo: no duplica ni modifica usuarios existentes.

### 5 y 6. Arranca la API y la web

**Opción A — un solo comando (recomendada):**

```bash
pnpm dev
```

Recompila los paquetes compartidos y arranca la API y la web a la vez en la misma terminal. Déjala abierta.

**Opción B — cada una en su terminal** (más fácil de leer los registros):

```bash
# Terminal 1: API
pnpm dev:api

# Terminal 2: web (cuando la API ya muestre «API escuchando en el puerto 3000»)
pnpm dev:web
```

✅ Comprobación de la API: abre `http://localhost:3000/api/v1/health`. Debe responder:

```json
{"status":"ok","database":"up"}
```

Si responde `"database":"down"`, PostgreSQL no está en marcha (vuelve al paso 2).

✅ Comprobación de la web: abre `http://localhost:5173`. Debe verse la página de inicio de AlertaSegura.

### 7. Inicia sesión

1. Abre `http://localhost:5173/login` o pulsa **Ingresar** en la barra superior.
2. Escribe el correo y la contraseña de un usuario (la que pusiste en el `.env`):

   | Correo | Contraseña (del `.env`) | Rol | Qué puede hacer |
   | --- | --- | --- | --- |
   | `admin@alertasegura.local` | `SEED_ADMIN_PASSWORD` | Administrador | Ver usuarios y auditoría (no publica) |
   | `auditor@alertasegura.local` | `SEED_AUDITOR_PASSWORD` | Auditor | Ver auditoría |
   | `emisor1@alertasegura.local` | `SEED_ISSUER1_PASSWORD` | Emisor | Crear y ver sus borradores |
   | `emisor2@alertasegura.local` | `SEED_ISSUER2_PASSWORD` | Emisor | Crear y ver sus borradores |

3. Pulsa **Ingresar**. Llegas a `/panel` con tu nombre, rol, permisos y las secciones disponibles.
4. Para salir, pulsa **Salir**.

Sin iniciar sesión puedes ver el inicio (`/`) y el laboratorio criptográfico (`/laboratorio/criptografia`).

---

## Día a día (cuando ya está inicializado)

No hay que repetir la instalación. Solo:

1. Abrir **Docker Desktop** y esperar a *Engine running*.
2. `pnpm db:up`
3. `pnpm dev`
4. Abrir `http://localhost:5173`.

Repite pasos de la primera vez solo en estos casos:

| Si… | Ejecuta |
| --- | --- |
| Hiciste `git pull` y cambiaron dependencias (`package.json` o `pnpm-lock.yaml`) | `pnpm install` y `pnpm build:packages` |
| Llegaron migraciones nuevas (`packages/database/prisma/migrations`) | `pnpm db:deploy` |
| Añadiste una contraseña `SEED_*` que antes faltaba | `pnpm db:seed` |

## Apagar (en orden inverso)

1. `Ctrl+C` en la terminal (o terminales) de `pnpm dev`: detiene la web y la API.
2. `pnpm db:down`: detiene PostgreSQL. **Los datos se conservan** para la próxima vez.
3. Opcional: cerrar Docker Desktop.

## Si algo falla

| Paso | Síntoma | Causa y solución |
| --- | --- | --- |
| 0.2 | `pnpm` no se reconoce | Ejecuta `corepack enable` (como administrador en Windows) y abre una terminal nueva |
| 2 | `failed to connect to the docker API` | Docker Desktop no está abierto o aún no arrancó |
| 2 | `port is already allocated` / puerto 5432 en uso | Otro PostgreSQL ocupa el puerto: cambia `POSTGRES_PORT` y `DATABASE_URL` (paso 0.3) |
| 3 | `P1000: Authentication failed` | La contraseña de `DATABASE_URL` no coincide con `POSTGRES_PASSWORD`. Si cambiaste la contraseña después de crear la base, la base conserva la antigua: vuelve a poner la original |
| 3–4 | `Can't reach database server` | PostgreSQL no está arriba: repite el paso 2 |
| 4 | `[seed] …: omitido` | Falta la contraseña de ese usuario o tiene menos de 12 caracteres |
| 5 | La API se cierra con un error de configuración | Falta una variable en `.env` o `CSRF_SECRET` sigue con el valor de ejemplo |
| 5 | `Cannot find module '@alertasegura/…'` o falta el cliente Prisma | Ejecuta `pnpm build:packages` (paso 0.4) |
| 5 | `EADDRINUSE :3000` | Ya hay una API corriendo: ciérrala o usa esa |
| 6 | `Port 5173 is already in use` | Ya hay una web de Vite abierta: ciérrala o usa esa |
| 7 | «Correo o contraseña incorrectos» | Usa exactamente la contraseña del `.env`. El seed no cambia la contraseña de un usuario ya existente |
| 7 | «Demasiados intentos» | 5 fallos bloquean esa cuenta 15 minutos; reiniciar la API también los reinicia |
| 7 | Te devuelve al login tras un rato | La sesión caduca a los 30 minutos sin actividad o a las 8 horas |

## Verificar que todo está bien (opcional)

Con la API y la web en marcha:

```bash
pnpm test                 # pruebas unitarias
pnpm test:e2e             # pruebas de la API contra PostgreSQL (usan su propia base temporal)
pnpm test:g1              # aceptación de la semana 1 (P01, P02a, P02b, P09); tarda ~1 min
pnpm test:cleanup         # muestra los borradores que dejaron las pruebas; añade -- --apply para borrarlos
```

Resultados de referencia de la semana 1: [`docs/evidence/semana1-cumplimiento.md`](evidence/semana1-cumplimiento.md).
