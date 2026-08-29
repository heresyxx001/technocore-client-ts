import { base58Decode } from "./base58.js";

const MULTICODEC_ED25519 = new Uint8Array([0xed, 0x01]);
const DID_PREFIX = "did:key:";
const MULTIBASE_LENGTH = 48;
const PUBLIC_KEY_LENGTH = 32;

/**
 * Parse a canonical Ed25519 did:key into the raw 32-byte public key.
 * Expects the form: did:key:z6Mk... (multibase base58btc with ed25519-pub prefix).
 */
export function publicKeyFromDid(did: string): Uint8Array {
  if (typeof did !== "string" || !did.startsWith(DID_PREFIX)) {
    throw new Error("DID must start with 'did:key:z6Mk'");
  }
  const multibase = did.slice(DID_PREFIX.length);
  if (multibase.length !== MULTIBASE_LENGTH || !multibase.startsWith("z6Mk")) {
    throw new Error("DID must be the canonical 48-character Ed25519 multibase form");
  }
  const decoded = base58Decode(multibase.slice(1)); // strip multibase 'z'
  if (decoded.length !== 34) {
    throw new Error("DID must contain an ed25519-pub key (34 bytes)");
  }
  if (decoded[0] !== MULTICODEC_ED25519[0] || decoded[1] !== MULTICODEC_ED25519[1]) {
    throw new Error("DID must contain an ed25519-pub key");
  }
  return decoded.slice(2);
}

/** Validate a Technocore room/identifier name. */
export function validateName(value: string, label = "room"): string {
  if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(value)) {
    throw new Error(`${label} must match ^[a-z0-9][a-z0-9_-]{0,47}$`);
  }
  return value;
}
