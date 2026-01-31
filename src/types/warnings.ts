/**
 * Validation warning type definitions
 */

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
