/**
 * Test helpers and fixtures
 */

import { beforeAll } from "bun:test";
import * as ed25519 from "@noble/ed25519";
import { encode as base64urlEncode } from "../src/utils/base64url.ts";

// Test key pair (generated once)
export let privateKey: Uint8Array;
export let publicKey: Uint8Array;
export let publicKeyHex: string;

// Initialize keys before tests run
beforeAll(async () => {
  privateKey = ed25519.utils.randomSecretKey();
  publicKey = await ed25519.getPublicKeyAsync(privateKey);
  publicKeyHex = Array.from(publicKey)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
});

/**
 * Create a signed JWT for testing
 */
export async function createToken(
  payload: Record<string, unknown>,
  options?: { privateKey?: Uint8Array }
): Promise<string> {
  const header = { alg: "EdDSA", typ: "JWT" };
  const headerB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(header))
  );
  const payloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(payload))
  );
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = options?.privateKey ?? privateKey;
  const signature = await ed25519.signAsync(
    new TextEncoder().encode(signingInput),
    key
  );
  const signatureB64 = base64urlEncode(signature);

  return `${signingInput}.${signatureB64}`;
}

/**
 * Get current timestamp + offset in seconds
 */
export function futureTimestamp(offsetSeconds: number): number {
  return Math.floor(Date.now() / 1000) + offsetSeconds;
}

/**
 * Get current timestamp - offset in seconds (past)
 */
export function pastTimestamp(offsetSeconds: number): number {
  return Math.floor(Date.now() / 1000) - offsetSeconds;
}
