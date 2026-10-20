# Diagramas de comportamiento — AlertaSegura (semana 1)

Cómo se conectan y se comportan las piezas del sistema. Están dibujados con **Mermaid**, que GitHub y VS Code (con la
extensión *Markdown Preview Mermaid Support*) muestran como gráficos. Todos reflejan el código real de la rama
`feat/semana-1`.

> **Versión editable en Excalidraw:** [`diagramas/alertasegura-arquitectura.excalidraw`](diagramas/alertasegura-arquitectura.excalidraw)
> (ábrelo en https://excalidraw.com con *Abrir* o arrastrándolo). Vista previa:
>
> ![Arquitectura de AlertaSegura](diagramas/alertasegura-arquitectura.png)

| # | Diagrama | Tipo |
| --- | --- | --- |
| 1 | [Vista general: cómo se conecta todo](#1-vista-general-cómo-se-conecta-todo) | Componentes |
| 2 | [Orden de arranque](#2-orden-de-arranque) | Flujo |
| 3 | [Cadena de controles de cada petición](#3-cadena-de-controles-de-cada-petición) | Actividad |
| 4 | [Carga de la PWA y obtención del token CSRF](#4-carga-de-la-pwa-y-obtención-del-token-csrf) | Secuencia |
| 5 | [Inicio de sesión](#5-inicio-de-sesión) | Secuencia |
| 6 | [Crear un borrador](#6-crear-un-borrador) | Secuencia |
| 7 | [Intento de publicar (P02a, P02b)](#7-intento-de-publicar-p02a-p02b) | Secuencia |
| 8 | [Rate limiting (P09)](#8-rate-limiting-p09) | Secuencia |
| 9 | [Cierre de sesión](#9-cierre-de-sesión) | Secuencia |
| 10 | [Ciclo de vida de una sesión](#10-ciclo-de-vida-de-una-sesión) | Estados |
| 11 | [Laboratorio criptográfico (P13)](#11-laboratorio-criptográfico-p13) | Secuencia |
| 12 | [Roles y permisos](#12-roles-y-permisos) | Componentes |
| 13 | [Modelo de datos](#13-modelo-de-datos) | Entidad-relación |
| 14 | [Auditoría append-only](#14-auditoría-append-only) | Secuencia |

---

## 1. Vista general: cómo se conecta todo

```mermaid
flowchart LR
    subgraph Navegador["🌐 Navegador (Chrome)"]
        UI["PWA React 19<br/>apps/web"]
        WC["Web Crypto<br/>crypto.subtle"]
        CK[("Cookies HttpOnly<br/>as_session · as_csrf")]
    end

    subgraph Vite["Vite dev server :5173"]
        PX["Proxy /api → :3000"]
    end

    subgraph API["API NestJS :3000 · /api/v1"]
        G["Guards globales<br/>rate limit → auth → CSRF → Zod → RBAC"]
        M["Módulos<br/>auth · users · drafts · audit · health"]
        PR["PrismaService<br/>@prisma/adapter-pg"]
    end

    subgraph Docker["🐳 Docker"]
        DB[("PostgreSQL 17<br/>User · Session · Draft · AuditLog")]
    end

    subgraph Paquetes["packages/"]
        SH["shared<br/>Zod, roles, permisos"]
        VE["verification<br/>JCS + ECDSA P-256"]
        DA["database<br/>Prisma + Argon2id"]
    end

    UI -- "fetch /api/v1/..." --> PX
    PX --> G --> M --> PR -- "SQL" --> DB
    CK -. "enviadas solas por el navegador" .-> PX
    UI --> VE --> WC
    UI -. importa .-> SH
    M -. importa .-> SH
    PR -. importa .-> DA
```

**Cómo se lee:**
- **Peticiones:** el navegador solo habla con Vite (`:5173`), y Vite reenvía todo `/api` a la API (`:3000`). Como para el
  navegador todo tiene el mismo origen, no hace falta CORS.
- **Cookies:** son `HttpOnly`, así que el JavaScript de la PWA no puede leerlas; el navegador las adjunta solo.
- **Base de datos:** la API es la única que habla con PostgreSQL.
- **Verificación de firmas:** ocurre en el navegador con Web Crypto. El frontend nunca tiene una clave privada.

---

## 2. Orden de arranque

```mermaid
flowchart TD
    A["1 · Docker Desktop<br/>Engine running"] --> B["2 · pnpm db:up<br/>PostgreSQL healthy"]
    B --> C["3 · pnpm db:deploy<br/>migraciones: tablas + triggers"]
    C --> D["4 · pnpm db:seed<br/>admin, auditor, emisor1, emisor2"]
    D --> E["5 · API NestJS<br/>lee .env, conecta a la BD"]
    E --> F["6 · Web Vite<br/>proxy hacia la API"]
    F --> G["7 · Navegador<br/>localhost:5173/login"]

    P0["0 · Solo la primera vez<br/>pnpm install · .env · pnpm build:packages"] -.-> E
    P0 -.-> F

    E -- "CSRF_SECRET de ejemplo<br/>o falta variable" --> X1["❌ La API no arranca"]
    E -- "BD apagada" --> X2["/health → database: down"]
```

---

## 3. Cadena de controles de cada petición

Los guards globales están registrados en `apps/api/src/app.module.ts` en este orden. El de **propiedad** es un guard de
ruta que Nest ejecuta después de los globales.

```mermaid
flowchart TD
    REQ(["Petición HTTP"]) --> RL{"1 · Rate limit<br/>global y login por IP<br/>¿dentro del cupo?"}
    RL -- No --> E429["429 RATE_LIMITED<br/>+ Retry-After<br/>📝 RATE_LIMITED"]
    RL -- Sí --> PUB{"¿Ruta @Public?"}

    PUB -- No --> AU{"2 · Autenticación<br/>¿cookie as_session válida,<br/>sin caducar ni revocar?"}
    AU -- "Sin cookie" --> E401["401 UNAUTHENTICATED<br/>📝 ACCESS_DENIED"]
    AU -- "Cookie inválida, caducada<br/>o revocada" --> E401b["401 UNAUTHENTICATED<br/>borra cookies<br/>📝 AUTH_SESSION_REJECTED"]
    AU -- Sí --> RU{"Rate limit por usuario<br/>120 / 60 s"}
    RU -- No --> E429
    RU -- Sí --> SAFE
    PUB -- Sí --> SAFE{"¿Método GET/HEAD?"}

    SAFE -- Sí --> ZOD
    SAFE -- "No (POST…)" --> CS{"3 · CSRF<br/>Origin = WEB_ORIGIN<br/>y X-CSRF-Token = cookie<br/>y HMAC válido para esta sesión"}
    CS -- No --> E403C["403 CSRF_INVALID<br/>📝 CSRF_REJECTED"]
    CS -- Sí --> ZOD{"4 · Validación Zod<br/>body / params estrictos"}

    ZOD -- No --> E400["400 VALIDATION_FAILED"]
    ZOD -- Sí --> RB{"5 · RBAC<br/>¿el rol tiene el permiso?"}
    RB -- No --> E403["403 FORBIDDEN<br/>📝 ACCESS_DENIED / PUBLICATION_DENIED"]
    RB -- Sí --> OW{"6 · Propiedad<br/>(solo /drafts/:id)<br/>¿es su borrador?"}
    OW -- "No existe" --> E404["404 NOT_FOUND"]
    OW -- "Es de otro" --> E403
    OW -- Sí --> OK(["✅ Controlador"])
```

📝 = evento que se escribe en `AuditLog`.

**Por qué en este orden:**
- **Rate limit primero:** frena a quien abusa antes de gastar CPU en Argon2id o en consultas a la base de datos.
- **Autenticación antes que CSRF:** un anónimo siempre recibe 401, nunca 403 (P02a).
- **Validación antes que RBAC:** un cuerpo malformado da 400 sin revelar si tienes permiso.

---

## 4. Carga de la PWA y obtención del token CSRF

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuario
    participant W as PWA (React)
    participant V as Vite :5173
    participant A as API NestJS
    participant DB as PostgreSQL

    U->>W: Abre http://localhost:5173
    W->>V: GET /api/v1/auth/me
    V->>A: (proxy)
    A->>A: AuthenticationGuard: ¿cookie as_session?
    alt Sin sesión
        A-->>W: 401 UNAUTHENTICATED
        W->>W: Estado = anónimo (muestra «Ingresar»)
    else Sesión válida
        A->>DB: SELECT Session WHERE tokenHash = sha256(cookie)
        DB-->>A: sesión + usuario
        A->>DB: UPDATE lastSeenAt
        A-->>W: 200 { user, rol, permisos }
        W->>W: Estado = autenticado
    end

    Note over W: Antes del primer POST
    W->>A: GET /api/v1/auth/csrf
    A->>A: token = nonce.HMAC(CSRF_SECRET, sesión|anon · nonce)
    A-->>W: 200 { csrfToken } + Set-Cookie as_csrf
    W->>W: Guarda el token solo en memoria<br/>(nunca en localStorage)
```

---

## 5. Inicio de sesión

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuario
    participant W as PWA
    participant A as API
    participant RL as RateLimitService<br/>(memoria)
    participant DB as PostgreSQL
    participant AU as AuditService

    U->>W: Escribe correo y contraseña · Ingresar
    W->>A: POST /auth/login<br/>X-CSRF-Token + cookie as_csrf (anónimo)
    A->>RL: Límite por IP (10 / 60 s)
    A->>A: CsrfGuard · ZodValidationGuard
    A->>RL: ¿Cuenta con < 5 fallos en 15 min?
    alt Cupo agotado
        A-->>W: 429 + Retry-After
    end
    A->>DB: SELECT User WHERE email
    A->>A: Argon2id.verify(hash ó señuelo, contraseña)
    alt Credenciales incorrectas, cuenta inexistente o DISABLED
        A->>RL: recordFailure(cuenta)
        A->>AU: AUTH_LOGIN_FAILED (reason)
        AU->>DB: INSERT AuditLog
        A-->>W: 401 INVALID_CREDENTIALS (mensaje genérico)
        W->>U: «Correo o contraseña incorrectos» y borra la contraseña
    else Correctas
        opt Ya había una sesión en el navegador
            A->>DB: UPDATE Session SET revokedAt (rotación)
        end
        A->>A: token = 32 bytes aleatorios
        A->>DB: INSERT Session (tokenHash = sha256(token), expira en 8 h)
        A->>A: Nuevo CSRF ligado a la sesión
        A->>AU: AUTH_LOGIN_SUCCEEDED
        AU->>DB: INSERT AuditLog
        A-->>W: 200 { user, csrfToken }<br/>Set-Cookie as_session (HttpOnly, SameSite=Strict)<br/>Set-Cookie as_csrf
        W->>U: Redirige a /panel
    end
```

---

## 6. Crear un borrador

```mermaid
sequenceDiagram
    autonumber
    actor E as Emisor 1
    participant W as PWA
    participant A as API
    participant DB as PostgreSQL

    E->>W: /panel/borradores · rellena título, cuerpo, severidad
    W->>A: POST /drafts<br/>cookies + X-CSRF-Token + Origin
    A->>A: RateLimit global → Auth (+ límite usuario 120/min) → CSRF
    A->>A: Zod: CreateDraftRequest (sin campos extra)
    A->>A: RBAC: ISSUER tiene drafts:create ✅
    alt Token CSRF caducado o rotado
        A-->>W: 403 CSRF_INVALID
        W->>A: GET /auth/csrf (token nuevo)
        W->>A: Reintenta el POST una sola vez
    end
    A->>DB: INSERT Draft (ownerId = emisor 1)
    A->>DB: INSERT AuditLog DRAFT_CREATED
    A-->>W: 201 { draft }
    W->>A: GET /drafts
    A->>DB: SELECT Draft WHERE ownerId = emisor 1
    A-->>W: 200 { drafts } (solo los suyos)
    W->>E: El borrador aparece en la lista
```

---

## 7. Intento de publicar (P02a, P02b)

En la semana 1 la publicación **se autoriza y se audita**, pero la firma real llega en la semana 2. Por eso, quien
cumple todos los controles recibe **501**.

```mermaid
sequenceDiagram
    autonumber
    actor X as Quien intenta publicar
    participant A as API
    participant DB as PostgreSQL

    X->>A: POST /drafts/:id/publish

    alt P02a · Anónimo (sin cookie)
        A->>DB: AuditLog ACCESS_DENIED (unauthenticated)
        A-->>X: 401 UNAUTHENTICATED
    else Sin X-CSRF-Token, token de otra sesión u Origin ajeno
        A->>DB: AuditLog CSRF_REJECTED
        A-->>X: 403 CSRF_INVALID
    else P02b · AUDITOR o ADMIN (sin alerts:publish)
        A->>DB: AuditLog PUBLICATION_DENIED
        A-->>X: 403 FORBIDDEN
    else P02b · Emisor B con el borrador de A
        A->>DB: SELECT Draft (ownerId ≠ B)
        A->>DB: AuditLog PUBLICATION_DENIED
        A-->>X: 403 FORBIDDEN
    else Emisor A, dueño, todo correcto
        A->>DB: AuditLog PUBLICATION_AUTHORIZED
        A-->>X: 501 PUBLICATION_NOT_IMPLEMENTED<br/>(la firma es de la semana 2)
    end
```

---

## 8. Rate limiting (P09)

Ventana deslizante en memoria. Hay cuatro límites independientes:

```mermaid
flowchart LR
    R(["Petición"]) --> GL{"Global<br/>300 / 60 s"}
    GL -->|ok| T{"¿Es login?"}
    T -->|Sí| IP{"Login por IP<br/>10 / 60 s"}
    IP -->|ok| AC{"Login por cuenta<br/>5 fallos / 15 min<br/>(solo cuentan fallos)"}
    T -->|No, con sesión| US{"Por usuario<br/>120 / 60 s"}
    AC -->|ok| SIG(["Continúa"])
    US -->|ok| SIG
    GL -->|excede| L["429 + Retry-After<br/>📝 RATE_LIMITED<br/>(máx. 1 por clave y minuto)"]
    IP -->|excede| L
    AC -->|excede| L
    US -->|excede| L
```

```mermaid
sequenceDiagram
    autonumber
    actor At as Atacante
    participant A as API
    participant RL as RateLimitService

    loop Intentos 1 a 5 con la misma cuenta
        At->>A: POST /auth/login (contraseña errónea)
        A->>RL: recordFailure(cuenta)
        A-->>At: 401
    end
    At->>A: Intento 6
    A->>RL: ensureBelow(cuenta) → agotado
    A-->>At: 429 + Retry-After (hasta 15 min)
    Note over A,RL: Otro usuario desde otra cuenta<br/>sigue pudiendo entrar (límite por cuenta)
```

---

## 9. Cierre de sesión

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuario
    participant W as PWA
    participant A as API
    participant DB as PostgreSQL

    U->>W: Salir
    W->>A: POST /auth/logout + X-CSRF-Token
    A->>DB: UPDATE Session SET revokedAt = now()
    A->>DB: INSERT AuditLog AUTH_LOGOUT
    A-->>W: 204 + borra cookies as_session y as_csrf
    W->>W: Olvida el token CSRF · estado anónimo
    W->>U: Vuelve a inicio
    Note over U,DB: Si alguien reutiliza la cookie antigua → 401 (sesión revocada)
```

---

## 10. Ciclo de vida de una sesión

```mermaid
stateDiagram-v2
    [*] --> Activa: login correcto<br/>INSERT Session (8 h)
    Activa --> Activa: petición autenticada<br/>actualiza lastSeenAt
    Activa --> Inactiva: 30 min sin peticiones
    Activa --> Caducada: 8 h desde el login
    Activa --> Revocada: logout
    Activa --> Revocada: nuevo login en el mismo navegador (rotación)
    Inactiva --> [*]: 401 → volver a iniciar sesión
    Caducada --> [*]: 401 → volver a iniciar sesión
    Revocada --> [*]: 401 → volver a iniciar sesión
```

---

## 11. Laboratorio criptográfico (P13)

Comprueba que una firma hecha en **Node.js** se verifica igual en el **navegador**, y que cualquier alteración se rechaza.

```mermaid
sequenceDiagram
    autonumber
    participant N as Node.js (generador)
    participant F as p13-vectors.json<br/>(solo clave pública)
    actor U as Usuario
    participant L as Laboratorio (PWA)
    participant V as packages/verification
    participant WC as Web Crypto

    Note over N: pnpm --filter @alertasegura/verification vectors
    N->>N: Clave P-256 efímera
    N->>N: JCS(documento) → bytes canónicos
    N->>N: ECDSA-SHA256 → firma P1363 (64 bytes)
    N->>F: Escribe JWK pública + firmas
    N->>N: Descarta la clave privada 🗑️

    U->>L: Abre /laboratorio/criptografia
    L->>F: Carga los vectores
    loop Cada vector
        L->>V: verify(documento, firma, JWK)
        V->>V: Rechaza JWK con «d» (privada)
        V->>V: JCS(documento) RFC 8785
        V->>WC: importKey(JWK, ECDSA P-256)
        V->>WC: verify(SHA-256, firma, bytes)
        WC-->>L: true → «Firma válida ✅»
    end

    U->>L: Alterar un campo / añadir una clave / invertir un bit
    L->>V: verify(documento alterado, …)
    V->>WC: verify(...)
    WC-->>L: false → «Firma INVÁLIDA ❌»
    U->>L: Restaurar original → vuelve a ser válida
```

```mermaid
flowchart LR
    D["Documento JSON<br/>{ b:1, a:'x' }"] --> J["JCS RFC 8785<br/>orden de claves, números<br/>y escapes canónicos"]
    J --> B["Bytes UTF-8<br/>{&quot;a&quot;:&quot;x&quot;,&quot;b&quot;:1}"]
    B --> H["SHA-256"]
    H --> S["ECDSA P-256<br/>firma r‖s (64 bytes)<br/>base64url"]
    K["Clave pública JWK<br/>kid = SHA-256(SPKI)"] --> S
```

---

## 12. Roles y permisos

```mermaid
flowchart LR
    ADMIN(["👤 ADMIN"]) --> P1["users:read"]
    ADMIN --> P2["issuers:provision"]
    ADMIN --> P3["audit:read"]
    ISSUER(["👤 ISSUER<br/>emisor1 / emisor2"]) --> P4["drafts:create"]
    ISSUER --> P5["drafts:read-own"]
    ISSUER --> P6["alerts:publish"]
    AUDITOR(["👤 AUDITOR"]) --> P3
    CIUD(["👤 Ciudadano<br/>(sin sesión)"]) --> P7["/ y /laboratorio<br/>(público)"]

    P1 --> R1["GET /admin/users"]
    P2 --> R2["POST /admin/issuers"]
    P3 --> R3["GET /audit"]
    P4 --> R4["POST /drafts"]
    P5 --> R5["GET /drafts · GET /drafts/:id<br/>+ propiedad"]
    P6 --> R6["POST /drafts/:id/publish<br/>+ propiedad"]
```

El ADMIN **no** tiene `alerts:publish`: separación de funciones, porque quien gestiona usuarios no puede emitir alertas.

---

## 13. Modelo de datos

```mermaid
erDiagram
    User ||--o{ Session : "tiene"
    User ||--o{ Draft : "es dueño de"
    User |o--o{ User : "creó (createdById)"

    User {
        uuid id PK
        string email UK "minúsculas"
        string displayName
        string passwordHash "Argon2id"
        Role role "ADMIN | ISSUER | AUDITOR"
        UserStatus status "ACTIVE | DISABLED"
        uuid createdById FK
    }
    Session {
        uuid id PK
        string tokenHash UK "SHA-256 del token"
        uuid userId FK
        timestamptz lastSeenAt "inactividad 30 min"
        timestamptz expiresAt "absoluta 8 h"
        timestamptz revokedAt "logout / rotación"
        string ip
        string userAgent
    }
    Draft {
        uuid id PK
        string title
        string body
        Severity severity "INFO | WARNING | CRITICAL"
        DraftStatus status "DRAFT"
        uuid ownerId FK
    }
    AuditLog {
        uuid id PK
        timestamptz occurredAt
        string action
        AuditOutcome outcome "SUCCESS | DENIED | FAILURE"
        uuid actorId "sin FK a propósito"
        string targetType
        string targetId
        json metadata
    }
```

`AuditLog` no tiene clave foránea hacia `User`, para que la evidencia sobreviva aunque cambie la tabla de usuarios.

---

## 14. Auditoría append-only

```mermaid
sequenceDiagram
    autonumber
    participant A as API (AuditService)
    participant T as Trigger PostgreSQL
    participant L as AuditLog
    actor X as Atacante con acceso a la BD

    A->>L: INSERT (login, logout, altas, denegaciones, 429…)
    L-->>A: ✅ insertado

    X->>T: UPDATE AuditLog SET …
    T-->>X: ❌ ERROR: append-only
    X->>T: DELETE FROM AuditLog
    T-->>X: ❌ ERROR: append-only
    X->>T: TRUNCATE AuditLog
    T-->>X: ❌ ERROR: append-only
    Note over T,L: En la semana 3 se añade la cadena HMAC (P08)<br/>para detectar alteraciones incluso del superusuario
```

**Eventos que se registran en la semana 1:**

| Evento | Cuándo |
| --- | --- |
| `AUTH_LOGIN_SUCCEEDED` / `AUTH_LOGIN_FAILED` | Login correcto o fallido (con motivo) |
| `AUTH_LOGOUT` | Cierre de sesión |
| `AUTH_SESSION_REJECTED` | Cookie ausente, inválida, caducada o revocada |
| `CSRF_REJECTED` | Falla el token CSRF o el `Origin` |
| `ACCESS_DENIED` | Petición sin sesión a una ruta protegida, o rol sin permiso |
| `RATE_LIMITED` | Se superó un límite (429) |
| `ISSUER_PROVISIONED` | El ADMIN da de alta un emisor |
| `DRAFT_CREATED` | Un emisor crea un borrador |
| `PUBLICATION_DENIED` / `PUBLICATION_AUTHORIZED` | Intento de publicar denegado o autorizado |
