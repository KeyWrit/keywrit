/**
 * Error creation utilities
 */

import type { ValidationError, ValidationErrorCode } from "./types/index.ts";

/**
 * Create a validation error
 */
export function createError(
  code: ValidationErrorCode,
  message: string,
  details?: Record<string, unknown>
): ValidationError {
  return details ? { code, message, details } : { code, message };
}

/**
 * Create a malformed token error
 */
export function malformedToken(reason: string): ValidationError {
  return createError("MALFORMED_TOKEN", `Malformed token: ${reason}`);
}

/**
 * Create an invalid header error
 */
export function invalidHeader(reason: string): ValidationError {
  return createError("INVALID_HEADER", `Invalid header: ${reason}`);
}

/**
 * Create an invalid payload error
 */
export function invalidPayload(reason: string): ValidationError {
  return createError("INVALID_PAYLOAD", `Invalid payload: ${reason}`);
}

/**
 * Create a signature verification failed error
 */
export function signatureVerificationFailed(): ValidationError {
  return createError(
    "SIGNATURE_VERIFICATION_FAILED",
    "Signature verification failed"
  );
}
