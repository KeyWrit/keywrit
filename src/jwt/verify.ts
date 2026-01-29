/**
 * JWT signature verification
 */

import type { DecodedJWT, ValidationError } from "../types/index.ts";
import { verify as ed25519Verify } from "../crypto/ed25519.ts";

/** Result of signature verification */
export type VerifyResult =
  | { success: true }
  | { success: false; error: ValidationError };

/**
 * Verify JWT signature using Ed25519
 */
export async function verifySignature(
  decoded: DecodedJWT,
  publicKey: Uint8Array
): Promise<VerifyResult> {
  const encoder = new TextEncoder();
  const message = encoder.encode(decoded.signingInput);

  const isValid = await ed25519Verify(decoded.signature, message, publicKey);

  if (!isValid) {
    return {
      success: false,
      error: {
        code: "SIGNATURE_VERIFICATION_FAILED",
        message: "JWT signature verification failed",
      },
    };
  }

  return { success: true };
}
