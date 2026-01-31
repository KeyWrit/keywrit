/**
 * Test helpers and fixtures
 */

import * as ed25519 from "@noble/ed25519";
import { beforeAll } from "vitest";
import { KEYWRIT_ISSUER, KEYWRIT_VERSION } from "../src/constants.ts";
import { encode as base64urlEncode } from "../src/utils/base64url.ts";

// Test key pair (generated once)
export let privateKey: Uint8Array;
export let publicKey: Uint8Array;
export let publicKeyHex: string;

// Default library ID for tests
export const TEST_REALM = "test-app";

// Initialize keys before tests run
beforeAll(async () => {
  privateKey = ed25519.utils.randomSecretKey();
  publicKey = await ed25519.getPublicKeyAsync(privateKey);
  publicKeyHex = Array.from(publicKey)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
});

/** Options for creating a test token */
export interface CreateTokenOptions {
  privateKey?: Uint8Array;
  /** Override the header (use for testing invalid headers) */
  header?: Record<string, unknown>;
  /** Set aud to a different value (default: TEST_REALM) */
  aud?: string | string[];
  /** Set iss to a different value (default: KEYWRIT_ISSUER) */
  iss?: string;
  /** Set kwv to a different value (only via header override) */
  kwv?: number;
}

/**
 * Create a signed JWT for testing
 * By default includes iss: "keywrit", aud: TEST_REALM, kwv: 1
 */
export async function createToken(
  payload: Record<string, unknown>,
  options?: CreateTokenOptions,
): Promise<string> {
  // Build header with KeyWrit version
  const header = options?.header ?? {
    alg: "EdDSA",
    typ: "JWT",
    kwv: options?.kwv ?? KEYWRIT_VERSION,
  };

  // Build payload with KeyWrit defaults
  const fullPayload = {
    iss: options?.iss ?? KEYWRIT_ISSUER,
    aud: options?.aud ?? TEST_REALM,
    ...payload,
  };

  const headerB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(header)),
  );
  const payloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(fullPayload)),
  );
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = options?.privateKey ?? privateKey;
  const signature = await ed25519.signAsync(
    new TextEncoder().encode(signingInput),
    key,
  );
  const signatureB64 = base64urlEncode(signature);

  return `${signingInput}.${signatureB64}`;
}

/**
 * Create a token without KeyWrit defaults (for testing invalid tokens)
 */
export async function createRawToken(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  options?: { privateKey?: Uint8Array },
): Promise<string> {
  const headerB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(header)),
  );
  const payloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = options?.privateKey ?? privateKey;
  const signature = await ed25519.signAsync(
    new TextEncoder().encode(signingInput),
    key,
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
