# @alertasegura/web

PWA de AlertaSegura construida con React, TypeScript y Vite.

- `src/app`: router y providers.
- `src/pages`: páginas asociadas a rutas.
- `src/components`: interfaz reutilizable.
- `src/features`: casos de uso agrupados por dominio.
- `src/lib`: cliente HTTP y adaptadores del navegador.
- `config`: configuración de Vite que se prueba aparte (TLS de laboratorio).

Ejecutar desde la raíz con `pnpm dev:web`.

## Rutas (D-3)

| Ruta | Contenido |
| --- | --- |
| `/alertas` | Consulta ciudadana, sin sesión. `/` redirige aquí |
| `/admin` | Panel con sesión (usuarios, borradores, auditoría). `/panel` y sus subrutas redirigen aquí |
| `/login` | Inicio de sesión del personal |
| `/laboratorio/criptografia` | Laboratorio de verificación de firmas |

Las comprobaciones de rol en pantalla son solo de interfaz: la API decide el acceso.

## TLS de laboratorio con mkcert (S2-45)

Por defecto Vite sirve HTTP en `http://localhost:5173`. Para probar con HTTPS (por ejemplo cookies `Secure`):

```bash
mkcert -install
mkdir -p secrets/tls
mkcert -cert-file secrets/tls/localhost.pem -key-file secrets/tls/localhost-key.pem localhost 127.0.0.1 ::1
LAB_TLS=1 pnpm dev:web          # https://localhost:5173
```

- `secrets/` está ignorada por Git: el certificado y la clave de `mkcert` **nunca se versionan**. Son solo de laboratorio.
- `LAB_TLS_CERT` y `LAB_TLS_KEY` cambian las rutas (relativas a la raíz del repositorio o absolutas).
- Con `LAB_TLS=1` y sin los archivos, Vite **no arranca** y explica cómo crearlos: no se degrada a HTTP en silencio.
- El proxy `/api` apunta a `http://localhost:3000`, o a `https://localhost:3000` con `LAB_TLS=1`. `API_TARGET`
  lo cambia (por ejemplo `API_TARGET=http://localhost:3200`).
- Si la API también usa un certificado de `mkcert`, Node debe confiar en su CA:
  `NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"`.
