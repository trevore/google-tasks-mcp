import process from "node:process";
import { Buffer } from "node:buffer";
import crypto from "node:crypto";

/**
 * OAuth security validators (T1 hardening).
 *
 * The upstream server validated neither the `redirect_uri` against a registered
 * client nor required PKCE, so `/callback` could 302 an auth code to an
 * attacker-controlled URL. Because `/register` is open (DCR), validating the
 * redirect_uri only against the *registered* client is insufficient — an
 * attacker can register their own client with an evil redirect_uri. The fix is a
 * server-wide **exact-match allowlist** of permitted redirect URIs, enforced at
 * `/register`, `/authorize`, and `/token`, plus **mandatory PKCE (S256)**.
 */

/** Permitted OAuth redirect URIs when none are configured (hosted Claude connector callback). */
const DEFAULT_REDIRECT_ALLOWLIST = ["https://claude.ai/api/mcp/auth_callback"];

/**
 * The configured redirect-URI allowlist. Set `OAUTH_REDIRECT_ALLOWLIST` to a
 * comma-separated list of exact URIs (e.g. add a loopback URI for Claude Code).
 * Falls back to the hosted-Claude callback.
 */
export function getRedirectAllowlist(
  env: Record<string, string | undefined> = process.env,
): string[] {
  const raw = env.OAUTH_REDIRECT_ALLOWLIST;
  if (!raw) return [...DEFAULT_REDIRECT_ALLOWLIST];
  const list = raw.split(",").map((s) => s.trim()).filter(Boolean);
  return list.length ? list : [...DEFAULT_REDIRECT_ALLOWLIST];
}

/** True iff `uri` is an exact member of `allowlist`. No prefix/substring matching. */
export function isAllowedRedirectUri(
  uri: string | undefined,
  allowlist: string[],
): boolean {
  if (!uri) return false;
  return allowlist.includes(uri);
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * Verify a PKCE S256 challenge: BASE64URL(SHA256(verifier)) === challenge,
 * compared in constant time. Returns false if either value is missing.
 */
export function verifyPkceS256(
  verifier: string | undefined,
  challenge: string | undefined,
): boolean {
  if (!verifier || !challenge) return false;
  const computed = base64UrlEncode(
    crypto.createHash("sha256").update(verifier).digest(),
  );
  const a = Buffer.from(computed);
  const b = Buffer.from(challenge);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
