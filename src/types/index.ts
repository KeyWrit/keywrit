/**
 * Type definitions barrel export
 */

// Configuration types
export type {
    PublicKeyInput,
    RevocationList,
    TimingOptions,
    ValidatorConfig,
} from "./config.ts";
// Error types
export type { ValidationError, ValidationErrorCode } from "./errors.ts";
// Helper types
export type {
    DomainCheckResult,
    ExpirationInfo,
    FlagCheckResult,
} from "./helpers.ts";
// JWT types
export type {
    DecodedJWT,
    JWTHeader,
    LicenseClaims,
    LicensePayload,
    StandardClaims,
} from "./jwt.ts";

// Result types
export type {
    ValidationFailure,
    ValidationResult,
    ValidationSuccess,
} from "./results.ts";
// Warning types
export type { ValidationWarning, ValidationWarningCode } from "./warnings.ts";
