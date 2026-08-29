import { describe, expect, it } from "vitest";

import { base58Decode, base58Encode } from "../src/base58.js";

const VECTORS: Array<[Uint8Array, string]> = [
  [new Uint8Array(0), ""],
  [new Uint8Array([0x00]), "1"],
  [new Uint8Array([0x00, 0x00]), "11"],
  [new TextEncoder().encode("hello world"), "StV1DL6CwTryKyV"],
];

describe("base58btc", () => {
  it("encodes known vectors", () => {
    for (const [raw, encoded] of VECTORS) {
      expect(base58Encode(raw)).toBe(encoded);
    }
  });

  it("decodes known vectors", () => {
    for (const [raw, encoded] of VECTORS) {
      expect(base58Decode(encoded)).toEqual(raw);
    }
  });

  it("round-trips random bytes", () => {
    const bytes = new Uint8Array(64);
    for (let i = 0; i < 50; i++) {
      crypto.getRandomValues(bytes);
      expect(base58Decode(base58Encode(bytes))).toEqual(bytes);
    }
  });

  it("rejects invalid characters", () => {
    expect(() => base58Decode("0OIl")).toThrow();
  });
});
