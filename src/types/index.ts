/**
 * Type definitions barrel export
 */

// JWT types
export type {
  JWTHeader,
  StandardClaims,
  LicenseClaims,
  LicensePayload,
  DecodedJWT,
} from "./jwt.ts";

// Configuration types
export type {
  PublicKeyInput,
  TimingOptions,
  RevocationList,
  ValidatorConfig,
} from "./config.ts";

// Error types
export type { ValidationErrorCode, ValidationError } from "./errors.ts";

// Warning types
export type { ValidationWarningCode, ValidationWarning } from "./warnings.ts";

// Result types
export type {
  ValidationSuccess,
  ValidationFailure,
  ValidationResult,
} from "./results.ts";

// Helper types
export type {
  FlagCheckResult,
  ExpirationInfo,
  DomainCheckResult,
} from "./helpers.ts";
