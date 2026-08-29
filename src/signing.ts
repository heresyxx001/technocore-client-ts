import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { base58Encode } from "./base58.js";

/** Re-export KeyObject type for consumers. */
export type { KeyObject };

/** Canonical Ed25519 multicodec prefix for did:key. */
export const MULTICODEC_ED25519 = new Uint8Array([0xed, 0x01]);

/**
 * Derive the public did:key identifier for an Ed25519 key pair.
 * Builds: did:key:z + base58btc(0xed01 || raw public key).
 */
export function didFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  const combined = new Uint8Array(2 + publicKey.length);
  combined.set(MULTICODEC_ED25519, 0);
  combined.set(publicKey, 2);
  const multibase = "z" + base58Encode(combined);
  if (!multibase.startsWith("z6Mk")) {
    throw new Error("generated an invalid Ed25519 did:key");
  }
  return "did:key:" + multibase;
}

/** Generate a fresh Ed25519 key pair and return { privateKeyObject, publicKeyBytes, did }. */
export function generateIdentity(): {
  keyObject: KeyObject;
  publicKeyBytes: Uint8Array;
  did: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  const raw = publicKeyBytes.slice(publicKeyBytes.length - 32);
  return { keyObject: privateKey, publicKeyBytes: raw, did: didFromPublicKey(raw) };
}

/** Sign a payload with an Ed25519 private key, returning unpadded base64url. */
export function signPayload(privateKey: KeyObject, payload: Uint8Array): string {
  const signature = sign(null, payload, privateKey);
  return signature.toString("base64url");
}

/** Verify a base64url Ed25519 signature against a public key. */
export function verifySignature(
  publicKey: Uint8Array,
  signature: string,
  payload: Uint8Array,
): boolean {
  return verify(null, payload, createPublicKeyFromRaw(publicKey), Buffer.from(signature, "base64url"));
}

/** Extract the raw 32-byte Ed25519 public key from a private KeyObject. */
export function publicKeyFromPrivate(privateKey: KeyObject): Uint8Array {
  const spki = new Uint8Array(
    createPublicKey(privateKey).export({ type: "spki", format: "der" }) as Buffer,
  );
  return spki.slice(spki.length - 32);
}

/** Wrap raw 32-byte Ed25519 public key into a KeyObject. */
export function createPublicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  const der = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(raw),
  ]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/** Create a high-resolution wall-clock nonce within the 19-digit limit. */
export function nextNonce(): string {
  return String(Date.now()).padStart(13, "0");
}

/** Random nonce for tests and special cases (19 digits max). */
export function randomNonce(): string {
  return randomBytes(8).readBigUInt64BE(0).toString();
}