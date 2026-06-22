import crypto from "node:crypto";
import process from "node:process";
import { Buffer } from "node:buffer";

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;
const ITERATIONS = 100000;

function getEncryptionKey(): Buffer {
  const secret = process.env.ENCRYPTION_SECRET;
  if (!secret) {
    throw new Error("ENCRYPTION_SECRET environment variable is not set");
  }
  if (secret.length < 32) {
    throw new Error("ENCRYPTION_SECRET must be at least 32 characters long");
  }

  // NOTE: This salt is a fixed, hardcoded constant — it is NOT per-record.
  // The derived key therefore depends solely on ENCRYPTION_SECRET, so two
  // deploys configured with identical secrets derive identical keys (and can
  // decrypt each other's tokens). Do NOT change this salt: doing so would
  // change the derived key and make all already-stored encrypted tokens
  // undecryptable.
  const salt = Buffer.from("google-tasks-mcp-salt");
  return crypto.pbkdf2Sync(secret, salt, ITERATIONS, KEY_LENGTH, "sha256");
}

export function encrypt(text: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  // These random salt bytes are prepended to each record but are NOT used in
  // key derivation (decrypt() reads them into a variable it never uses — see
  // `_salt` below). They are effectively decorative for this scheme. Semantic
  // security comes from the AES-GCM IV, which IS random per record (above).
  const salt = crypto.randomBytes(SALT_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");

  const tag = cipher.getAuthTag();

  const result = Buffer.concat([salt, iv, tag, Buffer.from(encrypted, "hex")]);
  return result.toString("base64");
}

export function decrypt(encryptedData: string): string {
  const key = getEncryptionKey();
  const buffer = Buffer.from(encryptedData, "base64");

  // The per-record salt is parsed out for layout/offset purposes only; it is
  // intentionally unused in key derivation (the key derives from the fixed
  // constant salt in getEncryptionKey()). The random per-record AES-GCM IV
  // below is what provides semantic security.
  const _salt = buffer.subarray(0, SALT_LENGTH);
  const iv = buffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = buffer.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + TAG_LENGTH
  );
  const encrypted = buffer.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encrypted.toString("hex"), "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}
