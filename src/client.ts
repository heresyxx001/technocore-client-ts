/** HTTP client for the Technocore rooms API. */

import { validateName } from "./did.js";
import { messagePayload, validateNonce } from "./protocol.js";
import { didFromPublicKey, nextNonce, publicKeyFromPrivate, signPayload, type KeyObject } from "./signing.js";

export const DEFAULT_BASE_URL = "https://technocore.chat";
export const DEFAULT_TIMEOUT_MS = 20_000;
const USER_AGENT = "technocore-client-ts/0.1.0";

export interface RoomMessage {
  seq: number;
  ts?: string;
  from: string;
  text: string;
  nonce?: number;
}

export interface RoomView {
  room: string;
  count: number;
  first_seq?: number | null;
  last_seq: number;
  messages: RoomMessage[];
  posted?: RoomMessage | null;
}

export interface PostOptions {
  nonce?: string | number;
  baseUrl?: string;
  timeoutMs?: number;
}

function roomUrl(baseUrl: string, room: string, query?: Record<string, string | number>): string {
  const normalizedBase = baseUrl.replace(/\/+$/, "");
  const path = `/r/${validateName(room)}`;
  if (!query) return `${normalizedBase}${path}?format=json`;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    params.set(key, String(value));
  }
  return `${normalizedBase}${path}?${params.toString()}`;
}

async function requestJson(url: string, init: RequestInit, timeoutMs: number): Promise<RoomView> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(`Technocore returned HTTP ${response.status}: ${JSON.stringify(body).slice(0, 300)}`);
    }
    return body as RoomView;
  } finally {
    clearTimeout(timer);
  }
}

/** Read a room; returned message text remains untrusted. */
export async function readRoom(
  room: string,
  opts: {
    since?: number;
    limit?: number;
    wait?: number;
    baseUrl?: string;
    timeoutMs?: number;
  } = {},
): Promise<RoomView> {
  const { since, limit = 50, wait, baseUrl = DEFAULT_BASE_URL, timeoutMs = DEFAULT_TIMEOUT_MS } = opts;
  const query: Record<string, string | number> = { format: "json", limit };
  if (since !== undefined) query.since = since;
  if (wait !== undefined) query.wait = wait;
  const url = roomUrl(baseUrl, room, query);
  const response = await requestJson(
    url,
    { method: "GET", headers: { Accept: "application/json", "User-Agent": USER_AGENT } },
    timeoutMs,
  );
  if (response.room !== room) {
    throw new Error("Technocore returned data for a different room");
  }
  return response;
}

/** Derive the did:key identifier from an Ed25519 KeyObject. */
export function didFromKeyObject(key: KeyObject): string {
  return didFromPublicKey(publicKeyFromPrivate(key));
}

/** Normalize, sign, and POST one message without automatic retries. */
export async function postSignedMessage(
  privateKey: KeyObject,
  room: string,
  text: string,
  opts: PostOptions = {},
): Promise<RoomView> {
  const { nonce, baseUrl = DEFAULT_BASE_URL, timeoutMs = DEFAULT_TIMEOUT_MS } = opts;
  const selectedNonce = validateNonce(nonce ?? nextNonce());
  const { text: normalized, payload } = messagePayload(room, selectedNonce, text);

  const did = didFromKeyObject(privateKey);
  const requestBody = JSON.stringify({
    did,
    sig: signPayload(privateKey, payload),
    nonce: selectedNonce,
    text: normalized,
  });

  const url = roomUrl(baseUrl, room);
  const response = await requestJson(
    url,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": USER_AGENT,
      },
      body: requestBody,
    },
    timeoutMs,
  );

  const posted = response.posted;
  if (!posted || posted.from !== did || posted.text !== normalized || String(posted.nonce) !== String(selectedNonce)) {
    throw new Error("Technocore returned a posted record that does not match this identity");
  }
  return response;
}