import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  getRedirectAllowlist,
  isAllowedRedirectUri,
  verifyPkceS256,
} from "./validation.ts";

test("default allowlist contains only the hosted Claude callback", () => {
  const a = getRedirectAllowlist({});
  assert.deepEqual(a, ["https://claude.ai/api/mcp/auth_callback"]);
});

test("OAUTH_REDIRECT_ALLOWLIST overrides with a trimmed comma list", () => {
  const a = getRedirectAllowlist({
    OAUTH_REDIRECT_ALLOWLIST:
      "https://claude.ai/api/mcp/auth_callback, http://127.0.0.1:8976/callback",
  });
  assert.deepEqual(a, [
    "https://claude.ai/api/mcp/auth_callback",
    "http://127.0.0.1:8976/callback",
  ]);
});

test("isAllowedRedirectUri is exact-match (T1: foreign redirect rejected)", () => {
  const a = ["https://claude.ai/api/mcp/auth_callback"];
  assert.equal(isAllowedRedirectUri("https://claude.ai/api/mcp/auth_callback", a), true);
  // the original T1 attack: an attacker-controlled redirect target
  assert.equal(isAllowedRedirectUri("https://attacker.example/grab", a), false);
  // no sneaky suffix/prefix matches
  assert.equal(isAllowedRedirectUri("https://claude.ai/api/mcp/auth_callback/", a), false);
  assert.equal(isAllowedRedirectUri("https://claude.ai.attacker.example/api/mcp/auth_callback", a), false);
  assert.equal(isAllowedRedirectUri(undefined, a), false);
});

test("verifyPkceS256 accepts a correct verifier/challenge pair", () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  assert.equal(verifyPkceS256(verifier, challenge), true);
});

test("verifyPkceS256 rejects wrong verifier and missing values", () => {
  const challenge = crypto.createHash("sha256").update("the-real-verifier").digest("base64url");
  assert.equal(verifyPkceS256("a-different-verifier", challenge), false);
  assert.equal(verifyPkceS256(undefined, challenge), false);
  assert.equal(verifyPkceS256("the-real-verifier", undefined), false);
});
