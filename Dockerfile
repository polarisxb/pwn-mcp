FROM node:20-slim AS base

WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY packages ./packages

RUN npm ci --silent && \
    npm run --workspace @pwn-mcp/core build && \
    npm run --workspace @pwn-mcp/config build && \
    npm run --workspace @pwn-mcp/storage build && \
    npm run --workspace @pwn-mcp/orchestrator build && \
    npm run --workspace @pwn-mcp/adapters build && \
    npm run --workspace @pwn-mcp/templates build && \
    npm run --workspace @pwn-mcp/mcp-server build

FROM node:20-slim
WORKDIR /app
COPY --from=base /app /app

# Optional tools; comment if not needed
RUN apt-get update && apt-get install -y --no-install-recommends rizin gdb \
  && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV SAFE_MCP_DEEP_STATIC=false
ENV SAFE_MCP_GDB_EXEC=false

CMD ["node", "packages/mcp-server/dist/server.js"] 