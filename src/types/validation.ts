/**
 * Validation result type definitions
 */

import type { LicensePayload } from "./jwt.ts";

/** Error codes for validation failures */
export type ValidationErrorCode =
  | "MALFORMED_TOKEN"
  | "INVALID_HEADER"
  | "INVALID_PAYLOAD"
  | "SIGNATURE_VERIFICATION_FAILED"
  | "TOKEN_EXPIRED"
  | "TOKEN_NOT_YET_VALID"
  | "TOKEN_REVOKED"
  | "CLAIM_MISMATCH"
  | "MISSING_REQUIRED_FLAG"
  | "MISSING_REQUIRED_FEATURE"
  | "KIND_MISMATCH"
  | "EXPIRATION_REQUIRED"
  | "INVALID_ISSUER"
  | "INVALID_AUDIENCE"
  | "UNSUPPORTED_VERSION";

/** Validation error with code and details */
export interface ValidationError {
  code: ValidationErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

/** Warning codes for non-fatal issues */
export type ValidationWarningCode =
  | "EXPIRING_SOON"
  | "NO_EXPIRATION"
  | "CLOCK_SKEW_APPLIED";

/** Validation warning */
export interface ValidationWarning {
  code: ValidationWarningCode;
  message: string;
  details?: Record<string, unknown>;
}

/** Successful validation result */
export interface ValidationSuccess<T = Record<string, unknown>> {
  valid: true;
  license: LicensePayload<T>;
  warnings?: ValidationWarning[];
}

/** Failed validation result */
export interface ValidationFailure {
  valid: false;
  error: ValidationError;
  errors?: ValidationError[];
  /** Unverified payload for debugging (available if parsing succeeded) */
  unverifiedPayload?: LicensePayload;
}

/** Discriminated union for validation results */
export type ValidationResult<T = Record<string, unknown>> =
  | ValidationSuccess<T>
  | ValidationFailure;

/** Result of a flag check */
export interface FlagCheckResult {
  enabled: boolean;
  /** Reason if not enabled */
  reason?: "not_in_license" | "invalid_token" | "expired";
}

/** Information about token expiration */
export interface ExpirationInfo {
  /** Expiration timestamp (null if no expiration) */
  expiresAt: number | null;
  /** Whether the token is currently expired */
  isExpired: boolean;
  /** Seconds until expiration (negative if expired, null if no expiration) */
  secondsRemaining: number | null;
  /** Human-readable time until expiration */
  timeRemaining: string | null;
}
