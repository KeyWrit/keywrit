/**
 * JWT decoding utilities
 */

import { SUPPORTED_VERSIONS } from "../constants.ts";
import type { DecodedJWT, JWTHeader, LicensePayload } from "../types/index.ts";
import { decode as base64urlDecode, decodeString } from "../utils/base64url.ts";

/** Validation result for decoding */
export type DecodeResult<T> =
  | { success: true; data: DecodedJWT<T> }
  | { success: false; error: string };

/**
 * Decode a JWT without verification
 * Returns structured error information instead of throwing
 */
export function decodeJWT<T = Record<string, unknown>>(
  token: string,
): DecodeResult<T> {
  // Split token into parts
  const parts = token.split(".");
  if (parts.length !== 3) {
    return {
      success: false,
      error: `Invalid token structure: expected 3 parts, got ${parts.length}`,
    };
  }

  const [headerB64, payloadB64, signatureB64] = parts as [
    string,
    string,
    string,
  ];

  // Decode header
  let header: JWTHeader;
  try {
    const headerJson = decodeString(headerB64);
    header = JSON.parse(headerJson) as JWTHeader;
  } catch {
    return { success: false, error: "Failed to decode header" };
  }

  // Validate header
  if (header.alg !== "EdDSA") {
    return {
      success: false,
      error: `Invalid algorithm: expected EdDSA, got ${header.alg}`,
    };
  }
  if (header.typ !== "JWT") {
    return {
      success: false,
      error: `Invalid type: expected JWT, got ${header.typ}`,
    };
  }

  // Validate KeyWrit version
  if (header.kwv === undefined) {
    return {
      success: false,
      error: "Missing KeyWrit version (kwv) in header",
    };
  }
  if (!SUPPORTED_VERSIONS.includes(header.kwv)) {
    return {
      success: false,
      error: `Unsupported KeyWrit version: ${header.kwv}. Supported versions: ${SUPPORTED_VERSIONS.join(", ")}`,
    };
  }

  // Decode payload
  let payload: LicensePayload<T>;
  try {
    const payloadJson = decodeString(payloadB64);
    payload = JSON.parse(payloadJson) as LicensePayload<T>;
  } catch {
    return { success: false, error: "Failed to decode payload" };
  }

  // Validate payload is an object
  if (typeof payload !== "object" || payload === null) {
    return { success: false, error: "Payload must be a JSON object" };
  }

  // Decode signature
  let signature: Uint8Array;
  try {
    signature = base64urlDecode(signatureB64);
  } catch {
    return { success: false, error: "Failed to decode signature" };
  }

  // Validate signature length (Ed25519 signatures are 64 bytes)
  if (signature.length !== 64) {
    return {
      success: false,
      error: `Invalid signature length: expected 64 bytes, got ${signature.length}`,
    };
  }

  return {
    success: true,
    data: {
      header,
      payload,
      signature,
      signingInput: `${headerB64}.${payloadB64}`,
    },
  };
}

/**
 * Decode just the payload without full validation
 * Useful for debugging or extracting info from potentially invalid tokens
 */
export function decodePayload<T = Record<string, unknown>>(
  token: string,
): LicensePayload<T> | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  try {
    const payloadJson = decodeString(parts[1]!);
    const payload = JSON.parse(payloadJson) as LicensePayload<T>;
    if (typeof payload !== "object" || payload === null) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

/**
 * Public decode function for external use
 * Returns null on any error
 */
export function decode<T = Record<string, unknown>>(
  token: string,
): DecodedJWT<T> | null {
  const result = decodeJWT<T>(token);
  return result.success ? result.data : null;
}
