import { describe, expect, it } from "vitest";

import { generateIdentity, signPayload, verifySignature, createPublicKeyFromRaw } from "../src/signing.js";
import { normalizeMessage, messagePayload, validateNonce } from "../src/protocol.js";

describe("signing", () => {
  it("signs and verifies a payload", () => {
    const { keyObject, publicKeyBytes } = generateIdentity();
    const payload = new TextEncoder().encode("lobby|42|hello");
    const sig = signPayload(keyObject, payload);
    expect(verifySignature(publicKeyBytes, sig, payload)).toBe(true);
  });

  it("rejects a tampered payload", () => {
    const { keyObject, publicKeyBytes } = generateIdentity();
    const sig = signPayload(keyObject, new TextEncoder().encode("original"));
    expect(verifySignature(publicKeyBytes, sig, new TextEncoder().encode("tampered"))).toBe(false);
  });

  it("verifies using a public key wrapped from raw bytes", async () => {
    const { keyObject, publicKeyBytes } = generateIdentity();
    const payload = new TextEncoder().encode("data");
    const sig = signPayload(keyObject, payload);
    const wrapped = createPublicKeyFromRaw(publicKeyBytes);
    const { verify } = await import("node:crypto");
    const ok = verify(null, payload, wrapped, Buffer.from(sig, "base64url"));
    expect(ok).toBe(true);
  });
});

describe("protocol", () => {
  it("normalizes invisible characters to spaces", () => {
    expect(normalizeMessage("  a\u0000b\tc  ")).toBe("a b c");
  });

  it("rejects empty messages", () => {
    expect(() => normalizeMessage("   \t ")).toThrow();
  });

  it("builds the exact payload", () => {
    const { text, payload } = messagePayload("lobby", "42", "  Hello, World!  ");
    expect(text).toBe("Hello, World!");
    expect(new TextDecoder().decode(payload)).toBe("lobby|42|Hello, World!");
  });

  it("validates nonces", () => {
    expect(validateNonce("123")).toBe("123");
    expect(() => validateNonce("abc")).toThrow();
    expect(() => validateNonce("")).toThrow();
  });
});
