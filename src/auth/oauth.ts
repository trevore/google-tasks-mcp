import { Buffer } from "node:buffer";
import { Hono } from "hono";
import { tokenStore } from "./token-store.ts";
import crypto from "node:crypto";
import process from "node:process";
import { openKv } from "@deno/kv";
import { createLogger } from "../utils/logger.ts";
import { rateLimit } from "../server/rate-limiter.ts";
import { getRedirectAllowlist, isAllowedRedirectUri, verifyPkceS256 } from "./validation.ts";

const logger = createLogger({ component: "oauth" });

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

interface OAuthSession {
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  redirectUri: string;
  clientId?: string;
}

interface AuthCode {
  googleCode: string;
  clientId?: string;
  redirectUri: string;
  codeChallenge?: string;
}

interface RegisteredClient {
  clientId: string;
  clientSecret?: string;
  redirectUris: string[];
}

class OAuthStore {
  private kv: Awaited<ReturnType<typeof openKv>> | null = null;

  async init() {
    this.kv = await openKv(process.env.DENO_KV_PATH);
  }

  async storeSession(sessionId: string, session: OAuthSession): Promise<void> {
    if (!this.kv) throw new Error("KV not initialized");
    await this.kv.set(["oauth_sessions", sessionId], session, { expireIn: 600000 });
  }

  async getSession(sessionId: string): Promise<OAuthSession | null> {
    if (!this.kv) throw new Error("KV not initialized");
    const result = await this.kv.get<OAuthSession>(["oauth_sessions", sessionId]);
    return result.value;
  }

  async deleteSession(sessionId: string): Promise<void> {
    if (!this.kv) throw new Error("KV not initialized");
    await this.kv.delete(["oauth_sessions", sessionId]);
  }

  async storeAuthCode(code: string, data: AuthCode): Promise<void> {
    if (!this.kv) throw new Error("KV not initialized");
    await this.kv.set(["auth_codes", code], data, { expireIn: 600000 });
  }

  async getAuthCode(code: string): Promise<AuthCode | null> {
    if (!this.kv) throw new Error("KV not initialized");
    const result = await this.kv.get<AuthCode>(["auth_codes", code]);
    return result.value;
  }

  async deleteAuthCode(code: string): Promise<void> {
    if (!this.kv) throw new Error("KV not initialized");
    await this.kv.delete(["auth_codes", code]);
  }

  async registerClient(clientId: string, client: RegisteredClient): Promise<void> {
    if (!this.kv) throw new Error("KV not initialized");
    await this.kv.set(["clients", clientId], client);
  }

  async getClient(clientId: string): Promise<RegisteredClient | null> {
    if (!this.kv) throw new Error("KV not initialized");
    const result = await this.kv.get<RegisteredClient>(["clients", clientId]);
    return result.value;
  }
}

const oauthStore = new OAuthStore();

export async function initOAuthStore() {
  await oauthStore.init();
}

export function createOAuthRouter(config: OAuthConfig) {
  const oauth = new Hono();

  oauth.post(
    "/register",
    rateLimit({ maxRequests: 30, windowMs: 3600000 }),
    async (c) => {
      const body = await c.req.json();
      const requestedRedirects: string[] = Array.isArray(body.redirect_uris)
        ? body.redirect_uris
        : [];

      // Open DCR endpoint: only allow registering redirect URIs that are in the
      // server allowlist, so a hostile registration cannot smuggle in an evil
      // redirect target (closes the T1 open-redirect class even with open DCR).
      const allowlist = getRedirectAllowlist();
      const invalid = requestedRedirects.filter((u) => !isAllowedRedirectUri(u, allowlist));
      if (requestedRedirects.length === 0 || invalid.length > 0) {
        logger.warn("OAuth client registration rejected: redirect_uri not allowlisted");
        return c.json({
          error: "invalid_redirect_uri",
          error_description: "redirect_uris must all be present in the server's OAUTH_REDIRECT_ALLOWLIST",
        }, 400);
      }

      const clientId = crypto.randomUUID();
      await oauthStore.registerClient(clientId, {
        clientId,
        redirectUris: requestedRedirects,
      });

      logger.info("OAuth client registered");

      return c.json({
        client_id: clientId,
        redirect_uris: requestedRedirects,
      });
    }
  );

  oauth.get(
    "/authorize",
    rateLimit({ maxRequests: 60, windowMs: 3600000 }),
    async (c) => {
    const responseType = c.req.query("response_type");
    const clientId = c.req.query("client_id");
    const redirectUri = c.req.query("redirect_uri");
    const state = c.req.query("state");
    const codeChallenge = c.req.query("code_challenge");
    const codeChallengeMethod = c.req.query("code_challenge_method");

    if (responseType !== "code") {
      logger.warn("OAuth authorization failed: unsupported response type");
      return c.json({ error: "unsupported_response_type" }, 400);
    }

    if (!clientId) {
      logger.warn("OAuth authorization failed: missing client_id");
      return c.json({ error: "invalid_request", error_description: "client_id is required" }, 400);
    }

    if (!redirectUri) {
      logger.warn("OAuth authorization failed: missing redirect_uri");
      return c.json({ error: "invalid_request", error_description: "redirect_uri is required" }, 400);
    }

    if (!state) {
      logger.warn("OAuth authorization failed: missing state parameter");
      return c.json({ error: "invalid_request", error_description: "state parameter is required for CSRF protection" }, 400);
    }

    // PKCE is mandatory (S256). Upstream only enforced PKCE when a challenge
    // happened to be present, letting an attacker simply omit it.
    if (!codeChallenge || codeChallengeMethod !== "S256") {
      logger.warn("OAuth authorization failed: PKCE S256 required");
      return c.json({ error: "invalid_request", error_description: "code_challenge with code_challenge_method=S256 is required" }, 400);
    }

    // redirect_uri must be server-allowlisted AND registered to this client.
    const allowlist = getRedirectAllowlist();
    if (!isAllowedRedirectUri(redirectUri, allowlist)) {
      logger.warn("OAuth authorization failed: redirect_uri not allowlisted");
      return c.json({ error: "invalid_request", error_description: "redirect_uri is not allowed" }, 400);
    }

    const client = await oauthStore.getClient(clientId);
    if (!client) {
      logger.warn("OAuth authorization failed: unknown client_id");
      return c.json({ error: "invalid_client", error_description: "unknown client_id" }, 400);
    }
    if (!client.redirectUris.includes(redirectUri)) {
      logger.warn("OAuth authorization failed: redirect_uri not registered for client");
      return c.json({ error: "invalid_request", error_description: "redirect_uri does not match a registered redirect_uri" }, 400);
    }

    logger.info("Starting OAuth authorization flow");

    const internalState = crypto.randomUUID();

    await oauthStore.storeSession(internalState, {
      state,
      codeChallenge,
      codeChallengeMethod,
      redirectUri,
      clientId,
    });

    const googleAuthUrl = new URL(GOOGLE_AUTH_URL);
    googleAuthUrl.searchParams.append("response_type", "code");
    googleAuthUrl.searchParams.append("client_id", config.clientId);
    googleAuthUrl.searchParams.append("redirect_uri", config.redirectUri);
    googleAuthUrl.searchParams.append("scope", "https://www.googleapis.com/auth/tasks");
    googleAuthUrl.searchParams.append("state", internalState);
    googleAuthUrl.searchParams.append("access_type", "offline");
    googleAuthUrl.searchParams.append("prompt", "consent");

    return c.redirect(googleAuthUrl.toString());
    }
  );

  oauth.get("/callback", async (c) => {
    const code = c.req.query("code");
    const internalState = c.req.query("state");

    if (!code || !internalState) {
      logger.warn("OAuth callback failed: missing code or state");
      return c.json({ error: "invalid_request" }, 400);
    }

    const session = await oauthStore.getSession(internalState);
    if (!session) {
      logger.warn("OAuth callback failed: invalid or expired state");
      return c.json({ error: "invalid_state" }, 400);
    }

    logger.info("Processing OAuth callback from Google");

    const authCode = crypto.randomUUID();

    await oauthStore.storeAuthCode(authCode, {
      googleCode: code,
      clientId: session.clientId,
      redirectUri: session.redirectUri,
      codeChallenge: session.codeChallenge,
    });

    await oauthStore.deleteSession(internalState);

    const redirectUrl = new URL(session.redirectUri);
    redirectUrl.searchParams.append("code", authCode);
    redirectUrl.searchParams.append("state", session.state);

    return c.redirect(redirectUrl.toString());
  });

  oauth.post(
    "/token",
    rateLimit({ maxRequests: 100, windowMs: 3600000 }),
    async (c) => {
    const body = await c.req.parseBody();
    const grantType = body.grant_type;
    const code = body.code as string;
    const codeVerifier = body.code_verifier as string;
    const redirectUri = body.redirect_uri as string;

    if (grantType !== "authorization_code") {
      logger.warn("Token exchange failed: unsupported grant type");
      return c.json({ error: "unsupported_grant_type" }, 400);
    }

    const authCodeData = await oauthStore.getAuthCode(code);
    if (!authCodeData) {
      logger.warn("Token exchange failed: invalid authorization code");
      return c.json({ error: "invalid_grant" }, 400);
    }

    logger.info("Processing token exchange request");

    if (redirectUri !== authCodeData.redirectUri) {
      logger.warn("Token exchange failed: redirect_uri mismatch");
      return c.json({ error: "invalid_grant", error_description: "redirect_uri does not match authorization request" }, 400);
    }

    if (!isAllowedRedirectUri(redirectUri, getRedirectAllowlist())) {
      logger.warn("Token exchange failed: redirect_uri not allowlisted");
      return c.json({ error: "invalid_grant", error_description: "redirect_uri is not allowed" }, 400);
    }

    // PKCE is mandatory: the auth code must carry a challenge and the verifier must match.
    if (!verifyPkceS256(codeVerifier, authCodeData.codeChallenge)) {
      logger.warn("PKCE validation failed");
      return c.json({ error: "invalid_grant", error_description: "invalid or missing PKCE code_verifier" }, 400);
    }

    try {
      const tokenResponse = await fetch(GOOGLE_TOKEN_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          code: authCodeData.googleCode,
          client_id: config.clientId,
          client_secret: config.clientSecret,
          redirect_uri: config.redirectUri,
          grant_type: "authorization_code",
        }),
      });

      const tokenData = await tokenResponse.json();

      if (!tokenResponse.ok) {
        logger.error("Google token exchange failed", { status: tokenResponse.status });
        return c.json({ error: "server_error", error_description: "Failed to exchange Google token" }, 500);
      }

      const mcpToken = crypto.randomUUID();

      await tokenStore.storeTokens(mcpToken, {
        googleAccessToken: tokenData.access_token,
        googleRefreshToken: tokenData.refresh_token,
        expiresAt: Date.now() + tokenData.expires_in * 1000,
      });

      await oauthStore.deleteAuthCode(code);

      logger.info("Token exchange completed successfully");

      const MCP_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

      return c.json({
        access_token: mcpToken,
        token_type: "Bearer",
        expires_in: MCP_TOKEN_TTL_SECONDS,
      });
    } catch (error) {
      logger.error("Token exchange error", { error: String(error) });
      return c.json({ error: "server_error", error_description: "Failed to exchange authorization code" }, 500);
    }
    }
  );

  return oauth;
}

export async function refreshGoogleToken(
  refreshToken: string,
  config: OAuthConfig
): Promise<{
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}> {
  logger.info("Refreshing Google access token");

  const tokenResponse = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      refresh_token: refreshToken,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      grant_type: "refresh_token",
    }),
  });

  const tokenData = await tokenResponse.json();

  if (!tokenResponse.ok) {
    logger.error("Google token refresh failed");
    throw new Error(`Failed to refresh Google token: ${tokenData.error}`);
  }

  logger.info("Token refresh completed successfully");

  return {
    accessToken: tokenData.access_token,
    refreshToken: tokenData.refresh_token || refreshToken,
    expiresIn: tokenData.expires_in,
  };
}
