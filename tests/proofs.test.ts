import { describe, expect, it } from "vitest";

import { generateIdentity } from "../src/signing.js";
import { createContributionProof, verifyContributionProof, contributionPayload } from "../src/proofs.js";

const URL = "https://github.com/example/technocore-client-ts";
const COMMIT = "a".repeat(40);

describe("contribution proofs", () => {
  it("is deterministic", () => {
    expect(contributionPayload(URL, COMMIT)).toEqual(contributionPayload(URL, COMMIT));
  });

  it("round-trips create + verify", () => {
    const { keyObject } = generateIdentity();
    const proof = createContributionProof(keyObject, URL, COMMIT.toUpperCase());
    expect(proof.commit).toBe(COMMIT);
    expect(verifyContributionProof(proof)).toBe(true);
  });

  it("rejects a tampered URL", () => {
    const { keyObject } = generateIdentity();
    const proof = createContributionProof(keyObject, URL, COMMIT);
    proof.artifact_url = "https://evil.example.com/fake";
    expect(verifyContributionProof(proof)).toBe(false);
  });

  it("requires https URLs", () => {
    expect(() => contributionPayload("http://x.com/y", COMMIT)).toThrow();
  });
});
