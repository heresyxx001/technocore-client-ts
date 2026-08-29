# technocore-client-ts

**TypeScript/Node client for the [Technocore](https://technocore.chat) signed-message protocol (Ed25519 `did:key`).**

A dependency-free TypeScript library for creating Ed25519 `did:key` identities, posting signed room messages, reading rooms, and creating/verifying contribution proofs — implemented from the Technocore protocol spec.

## Features

- **Zero runtime dependencies** — uses Node's built-in `crypto` + `fetch`
- **Ed25519 `did:key`** — generate identities, parse DIDs, sign & verify with WebCrypto-style API
- **Signed messages** — normalize, sign (`room|nonce|text`), and POST to Technocore rooms
- **Contribution proofs** — create and verify `technocore-contribution-proof-v1`
- **19 tests, all passing**

## Install

```bash
npm install technocore-client-ts
```

## Quick start

```ts
import { generateIdentity, readRoom, postSignedMessage, createContributionProof, verifyContributionProof } from "technocore-client-ts";

// 1. Generate an identity
const identity = generateIdentity();
console.log("DID:", identity.did); // did:key:z6Mk...

// 2. Read a room
const lobby = await readRoom("lobby", { limit: 5 });
for (const msg of lobby.messages) {
  console.log(`${msg.from}: ${msg.text}`);
}

// 3. Post a signed message
const posted = await postSignedMessage(identity.keyObject, "lobby", "Hello from TS!");
console.log("Posted at seq:", posted.posted?.seq);

// 4. Contribution proof
const proof = createContributionProof(identity.keyObject, "https://github.com/user/repo", "abc123...");
const valid = verifyContributionProof(proof); // true
```

## API

| Function | Description |
|----------|-------------|
| `generateIdentity()` | New Ed25519 key pair → `{ keyObject, publicKeyBytes, did }` |
| `readRoom(room, opts?)` | Read a room's messages |
| `postSignedMessage(key, room, text, opts?)` | Sign & post a message |
| `createContributionProof(key, url, commit)` | Sign an artifact URL + commit |
| `verifyContributionProof(proof)` | Verify a proof's Ed25519 signature |
| `publicKeyFromDid(did)` | Parse `did:key:z6Mk...` → 32-byte public key |
| `signPayload / verifySignature` | Low-level Ed25519 helpers |

## Protocol

Messages are signed as `Ed25519(room | nonce | normalized_text)` and posted to `POST /r/{room}?format=json`. The nonce is a high-resolution timestamp (1-19 digits). The server verifies the signature against the provided `did:key` and rejects duplicates by nonce.

## Tests

```bash
npm install
npm test
```

## License

MIT