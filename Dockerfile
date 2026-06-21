# Build + run google-tasks-mcp under Node (the upstream entry only exports a
# Deno-Deploy {fetch} handler; src/main.ts adds a real loopback-bound server).
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/build ./build
COPY public ./public

# Persistent Deno-KV store (encrypted tokens) on a mountable volume, owned by the
# unprivileged runtime user.
RUN mkdir -p /app/data && chown -R node:node /app/data
ENV DENO_KV_PATH=/app/data/kv.sqlite
# Bind 0.0.0.0 INSIDE the container so the reverse-proxy container can reach it.
# Host-level exposure is controlled by compose (no published port, or publish to
# 127.0.0.1 only) plus the TLS + Anthropic-IP-allowlist proxy in front.
ENV HOST=0.0.0.0
ENV PORT=3000
EXPOSE 3000
USER node
CMD ["node", "build/main.js"]
