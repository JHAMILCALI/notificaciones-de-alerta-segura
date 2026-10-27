# API de AlertaSegura (S2-27). Se construye desde la raíz del repositorio (context: ..).
#
#   tools   -> instalación completa con las herramientas de Prisma: la usa el servicio `migrate` del compose
#              (prisma migrate deploy + pnpm db:roles con el rol propietario).
#   runtime -> la API en ejecución: solo dependencias de producción, usuario 10002 y sistema de archivos de solo lectura.
FROM node:24-alpine AS tools

WORKDIR /workspace
RUN corepack enable

# Las capas de dependencias solo dependen de los manifiestos, no del código.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/api/package.json apps/api/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/database/package.json packages/database/package.json
RUN pnpm install --filter @alertasegura/api... --frozen-lockfile

COPY packages/shared packages/shared
COPY packages/database packages/database
COPY apps/api apps/api

# `prisma generate` lee prisma.config.ts, que exige una URL aunque no se conecte: se usa una ficticia solo en este paso.
RUN DATABASE_URL=postgresql://build:build@localhost:5432/build pnpm --filter @alertasegura/api... build \
 && pnpm --filter @alertasegura/api deploy --prod --legacy /out

# Por defecto, un shell: el compose indica el comando de cada servicio.
CMD ["sh"]

FROM node:24-alpine AS runtime

# /run/signer es el volumen del socket del firmante (dueño 10001, grupo 10001, modo 0750): la API, usuario 10002,
# entra con el grupo suplementario 10001 (`group_add` en el compose). El socket es 0660 y también del grupo 10001.
# La clave privada del firmante NO está en esta imagen ni se monta aquí (P15).
RUN mkdir -p /run/signer /app \
 && chown 10001:10001 /run/signer \
 && chmod 0750 /run/signer

WORKDIR /app
COPY --from=tools --chown=0:0 /out/ ./

ENV NODE_ENV=production \
    PORT=3000 \
    SIGNER_SOCKET_PATH=/run/signer/signer.sock

USER 10002:10002
EXPOSE 3000
VOLUME ["/run/signer"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["node", "-e", "require('http').get({host:'127.0.0.1',port:process.env.PORT,path:'/api/v1/health'},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

# El compose activa read_only: true; la API no escribe en disco.
CMD ["node", "dist/main"]
