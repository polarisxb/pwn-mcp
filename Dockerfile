FROM node:20-slim AS base

WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages ./packages

RUN npm ci && \
    npm --prefix packages/core run build && \
    npm --prefix packages/config run build && \
    npm --prefix packages/storage run build && \
    npm --prefix packages/orchestrator run build && \
    npm --prefix packages/adapters run build && \
    npm --prefix packages/templates run build && \
    npm --prefix packages/mcp-server run build

FROM node:20-slim
WORKDIR /app
COPY --from=base /app /app

# Optional tools; comment if not needed
RUN apt-get update && \
  apt-get install -y --no-install-recommends gdb && \
  apt-get install -y --no-install-recommends rizin || true && \
  rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV SAFE_MCP_DEEP_STATIC=false
ENV SAFE_MCP_GDB_EXEC=false

CMD ["node", "packages/mcp-server/dist/server.js"] 