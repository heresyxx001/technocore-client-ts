/** Protocol-level validation and payload construction (mirrors Technocore). */

import { validateName } from "./did.js";

export const MAX_MESSAGE_CHARS = 4096;
export const NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;
export const NONCE_PATTERN = /^[0-9]{1,19}$/;
export const COMMIT_PATTERN = /^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/;

const INVISIBLE_CATEGORIES = new Set(["Cc", "Cf", "Cs", "Co", "Zl", "Zp"]);

function isInvisible(ch: string): boolean {
  // Very small subset for JS: control chars and common format chars.
  if (INVISIBLE_CATEGORIES.has(ch)) return true;
  const code = ch.codePointAt(0) ?? 0;
  return (
    (code >= 0x0000 && code <= 0x001f) ||
    (code >= 0x007f && code <= 0x009f) ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2060 && code <= 0x206f)
  );
}

/** Normalize message text the same way the Technocore server does. */
export function normalizeMessage(text: string): string {
  if (typeof text !== "string") {
    throw new Error("message text must be a string");
  }
  const normalized = Array.from(text)
    .map((ch) => (isInvisible(ch) ? " " : ch))
    .join("")
    .trim();
  if (!normalized) {
    throw new Error("message has no visible text after normalization");
  }
  if (normalized.length > MAX_MESSAGE_CHARS) {
    throw new Error(`message has ${normalized.length} characters; maximum is ${MAX_MESSAGE_CHARS}`);
  }
  return normalized;
}

/** Validate a Technocore nonce string (1-19 ASCII digits). */
export function validateNonce(value: string | number): string {
  const nonce = String(value);
  if (!NONCE_PATTERN.test(nonce)) {
    throw new Error("nonce must contain 1-19 ASCII digits");
  }
  return nonce;
}

/** Build the normalized message and the exact signed payload: room|nonce|text. */
export function messagePayload(room: string, nonce: string | number, text: string): { text: string; payload: Uint8Array } {
  const validRoom = validateName(room);
  const validNonce = validateNonce(nonce);
  const normalized = normalizeMessage(text);
  return {
    text: normalized,
    payload: new TextEncoder().encode(`${validRoom}|${validNonce}|${normalized}`),
  };
}
