/** technocore-client-ts — TypeScript client for the Technocore signed-message protocol. */

export { base58Encode, base58Decode } from "./base58.js";
export { publicKeyFromDid, validateName } from "./did.js";
export { generateIdentity, signPayload, verifySignature, didFromPublicKey, createPublicKeyFromRaw, nextNonce } from "./signing.js";
export { normalizeMessage, validateNonce, messagePayload, MAX_MESSAGE_CHARS } from "./protocol.js";
export { readRoom, postSignedMessage, didFromKeyObject, DEFAULT_BASE_URL, DEFAULT_TIMEOUT_MS } from "./client.js";
export { createContributionProof, verifyContributionProof, contributionPayload, PROOF_SCHEMA, RECORD_SCHEMA } from "./proofs.js";
export type { RoomMessage, RoomView, PostOptions } from "./client.js";
export type { ContributionProof } from "./proofs.js";
