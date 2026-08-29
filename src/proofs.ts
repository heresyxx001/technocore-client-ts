/** Signed contribution proofs tying a DID to a public Git revision. */

import { publicKeyFromDid } from "./did.js";
import { didFromPublicKey, publicKeyFromPrivate, signPayload, verifySignature, type KeyObject } from "./signing.js";
import { COMMIT_PATTERN } from "./protocol.js";

export const PROOF_SCHEMA = "technocore-contribution-proof-v1";
export const RECORD_SCHEMA = "technocore-contribution-v1";

export interface ContributionProof {
  schema: string;
  did: string;
  artifact_url: string;
  commit: string;
  signature: string;
}

/** Build the canonical deterministic payload for a contribution proof. */
export function contributionPayload(artifactUrl: string, commit: string): Uint8Array {
  if (!/^https:\/\/[^\s]+$/.test(artifactUrl)) {
    throw new Error("artifact URL must be an absolute HTTPS URL");
  }
  if (!COMMIT_PATTERN.test(commit)) {
    throw new Error("commit must be a complete 40- or 64-character hexadecimal revision");
  }
  const record = {
    artifact_url: artifactUrl,
    commit: commit.toLowerCase(),
    schema: RECORD_SCHEMA,
  };
  const canonical = JSON.stringify(record, Object.keys(record).sort());
  return new TextEncoder().encode(canonical);
}

/** Sign a public artifact URL + commit into a contribution proof. */
export function createContributionProof(
  privateKey: KeyObject,
  artifactUrl: string,
  commit: string,
): ContributionProof {
  const payload = contributionPayload(artifactUrl, commit);
  const raw = publicKeyFromPrivate(privateKey);
  return {
    schema: PROOF_SCHEMA,
    did: didFromPublicKey(raw),
    artifact_url: artifactUrl,
    commit: commit.toLowerCase(),
    signature: signPayload(privateKey, payload),
  };
}

/** Verify a contribution proof's shape and Ed25519 signature. */
export function verifyContributionProof(proof: ContributionProof): boolean {
  if (proof.schema !== PROOF_SCHEMA) {
    throw new Error("unsupported contribution proof schema");
  }
  const required = ["did", "artifact_url", "commit", "signature"] as const;
  for (const key of required) {
    if (typeof proof[key] !== "string" || !proof[key]) {
      throw new Error(`contribution proof is missing required string field: ${key}`);
    }
  }
  const payload = contributionPayload(proof.artifact_url, proof.commit);
  const raw = publicKeyFromDid(proof.did);
  return verifySignature(raw, proof.signature, payload);
}