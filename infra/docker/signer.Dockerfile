# Firmante aislado (S2-15). Se construye desde la raíz del repositorio (context: ..).
#
# Etapa de compilación: instala, compila los paquetes de los que depende y empaqueta el firmante en un
# solo archivo (esbuild), de modo que la imagen final no lleva node_modules ni código fuente.
FROM node:24-alpine AS build

WORKDIR /workspace
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/signer/package.json apps/signer/package.json
COPY packages/shared/package.json packages/shared/tsconfig.json packages/shared/
COPY packages/verification/package.json packages/verification/tsconfig.json packages/verification/tsconfig.build.json packages/verification/
RUN pnpm install --filter @alertasegura/signer... --frozen-lockfile

COPY packages/shared packages/shared
COPY packages/verification/src packages/verification/src
COPY apps/signer apps/signer
RUN pnpm --filter @alertasegura/signer... build

# Etapa final: usuario sin privilegios 10001, sin shell de instalación y con el socket en un volumen.
FROM node:24-alpine AS runtime

# /run/signer es el volumen del socket (lo comparte solo el contenedor de la API). Se crea con dueño 10001 y
# modo 0750 para que un volumen nuevo herede ese dueño. La clave se monta en /run/secrets/signer-private-key.pem
# (0400, dueño 10001) y nunca forma parte de la imagen.
RUN mkdir -p /run/signer /app \
 && chown 10001:10001 /run/signer \
 && chmod 0750 /run/signer

WORKDIR /app
COPY --from=build --chown=0:0 /workspace/apps/signer/dist/main.js ./main.js

# SIGNER_PRIVATE_KEY_PATH lo fija el compose (/run/secrets/signer-private-key.pem).
ENV NODE_ENV=production \
    SIGNER_SOCKET_PATH=/run/signer/signer.sock

USER 10001:10001
VOLUME ["/run/signer"]

# El estado se consulta por el socket, igual que lo hace la API.
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
  CMD ["node", "-e", "require('http').get({socketPath:process.env.SIGNER_SOCKET_PATH,path:'/health'},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

# Sistema de archivos de solo lectura: el compose lo activa con read_only: true.
CMD ["node", "main.js"]
