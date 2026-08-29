import { describe, expect, it } from "vitest";

import { generateIdentity } from "../src/signing.js";
import { publicKeyFromDid, validateName } from "../src/did.js";

describe("did:key", () => {
  it("generates a canonical did:key", () => {
    const { did } = generateIdentity();
    expect(did.startsWith("did:key:z6Mk")).toBe(true);
    expect(did.length).toBe("did:key:".length + 48);
  });

  it("parses back to the same public key", () => {
    const { publicKeyBytes, did } = generateIdentity();
    expect(publicKeyFromDid(did)).toEqual(publicKeyBytes);
  });

  it("rejects invalid DIDs", () => {
    expect(() => publicKeyFromDid("not-a-did")).toThrow();
    expect(() => publicKeyFromDid("did:key:z6Mk" + "x".repeat(41))).toThrow();
  });

  it("validates room names", () => {
    for (const ok of ["lobby", "technocore", "room-1", "x".repeat(48)]) {
      expect(validateName(ok)).toBe(ok);
    }
    for (const bad of ["", "-x", "X", "has space", "x".repeat(49)]) {
      expect(() => validateName(bad)).toThrow();
    }
  });
});
