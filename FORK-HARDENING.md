# Fork hardening (trevore/google-tasks-mcp)

Fork of `akutishevsky/google-tasks-mcp`, hardened before exposing it as an
OAuth-protected remote Claude connector. Based on the 2026-06-20 security audit.

## Changes vs upstream

- **T1 — OAuth open-redirect → token theft (HIGH), fixed.** Upstream `/authorize`
  never validated `redirect_uri` and PKCE was optional; combined with the open
  `/register` (DCR) endpoint, an attacker could obtain a 30-day full read/write
  Tasks token. Fixes (`src/auth/oauth.ts`, `src/auth/validation.ts`):
  - server-wide **exact-match redirect_uri allowlist**, enforced at `/register`,
    `/authorize`, and `/token`;
  - **mandatory PKCE S256** at `/authorize`, verified (constant-time) at `/token`;
  - `/authorize` now requires `client_id` and checks `redirect_uri` against the
    registered client.
- **T5 — no server socket, fixed.** Upstream entry only exported a Deno-Deploy
  `{ fetch }` handler. `src/main.ts` runs the app under Node via
  `@hono/node-server`, binding `HOST`/`PORT`. A `Dockerfile` is included.
- **Token persistence.** `DENO_KV_PATH` makes the encrypted token store persist
  across restarts (mount a volume at that path).

Unchanged: Google scope (`auth/tasks`), AES-256-GCM token encryption, the data path.

## Environment variables

| Var | Purpose |
|-----|---------|
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth client (server federates to Google) |
| `GOOGLE_REDIRECT_URI` | `https://gtasks.ellermann.net/callback` |
| `ENCRYPTION_SECRET` | ≥32 chars; `npm run generate-secret`. Encrypts tokens at rest |
| `OAUTH_REDIRECT_ALLOWLIST` | Comma-separated exact redirect URIs. Default `https://claude.ai/api/mcp/auth_callback` |
| `HOST` / `PORT` | Listen address (default `127.0.0.1:3000`; Docker sets `0.0.0.0`) |
| `DENO_KV_PATH` | Path to the persistent KV store (Docker: `/app/data/kv.sqlite`) |

## Run

```bash
npm ci && npm run build && node build/main.js     # local
docker build -t google-tasks-mcp . && docker run --env-file .env -p 127.0.0.1:3000:3000 google-tasks-mcp
```

Connector URL: `https://gtasks.ellermann.net/mcp`. Must sit behind TLS + an
Anthropic-IP allowlist (see the deploy runbook).

## Tests

```bash
node --test src/auth/validation.test.ts   # redirect-uri allowlist + PKCE S256
```
