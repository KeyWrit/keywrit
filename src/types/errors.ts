/**
 * Validation error type definitions
 */

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
    | "UNSUPPORTED_VERSION"
    | "DOMAIN_NOT_ALLOWED";

/** Validation error with code and details */
export interface ValidationError {
    code: ValidationErrorCode;
    message: string;
    details?: Record<string, unknown>;
}
