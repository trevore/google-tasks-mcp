#!/usr/bin/env node
/**
 * Node serving entrypoint.
 *
 * The upstream `index.ts` only exports a Deno-Deploy-style `{ fetch }` handler —
 * it opens no socket and ignores PORT (audit finding T5). This entrypoint runs
 * the same app under Node via `@hono/node-server`, binding the loopback by
 * default so exposure is an explicit reverse-proxy decision.
 */
import process from "node:process";
import { serve } from "@hono/node-server";
import { initOAuthStore } from "./auth/oauth.ts";
import { tokenStore } from "./auth/token-store.ts";
import { createApp } from "./server/app.ts";
import { setOAuthConfig } from "./config.ts";
import { initRateLimiter } from "./server/rate-limiter.ts";
import { createLogger } from "./utils/logger.ts";

const logger = createLogger({ component: "main" });

await tokenStore.init();
await initOAuthStore();
await initRateLimiter();

const oauthConfig = {
  clientId: process.env.GOOGLE_CLIENT_ID || "",
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
  redirectUri: process.env.GOOGLE_REDIRECT_URI || "",
};
setOAuthConfig(oauthConfig);

const app = createApp({ oauthConfig });

const port = Number(process.env.PORT || 3000);
// Bind loopback by default; the deploy puts TLS + an IP allowlist in front.
const hostname = process.env.HOST || "127.0.0.1";

serve({ fetch: app.fetch, port, hostname }, (info) => {
  logger.info("google-tasks-mcp listening", { hostname, port: info.port });
});
