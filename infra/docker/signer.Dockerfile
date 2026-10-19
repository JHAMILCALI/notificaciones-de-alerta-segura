FROM node:24-alpine AS build

WORKDIR /workspace
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/signer/package.json apps/signer/package.json
COPY packages/shared/package.json packages/shared/tsconfig.json packages/shared/
RUN pnpm install --filter @alertasegura/signer... --frozen-lockfile

COPY packages/shared packages/shared
COPY apps/signer apps/signer
RUN pnpm --filter @alertasegura/signer... build

FROM node:24-alpine AS runtime
WORKDIR /app
USER node
COPY --from=build --chown=node:node /workspace/apps/signer/dist ./dist
CMD ["node", "dist/main.js"]
