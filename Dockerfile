# syntax=docker/dockerfile:1

FROM node:20-slim AS builder

WORKDIR /app

# Copy manifests and workspace packages
COPY package.json package-lock.json ./
COPY packages ./packages

# Install dependencies
RUN npm ci

# Build all workspaces in order
RUN npm -w @pwn-mcp/core run build \
 && npm -w @pwn-mcp/config run build \
 && npm -w @pwn-mcp/storage run build \
 && npm -w @pwn-mcp/orchestrator run build \
 && npm -w @pwn-mcp/adapters run build \
 && npm -w @pwn-mcp/templates run build \
 && npm -w @pwn-mcp/mcp-server run build

# Prune dev dependencies for production runtime
RUN npm prune --omit=dev

FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app /app

EXPOSE 8888
CMD ["node", "packages/mcp-server/dist/server.js"]
