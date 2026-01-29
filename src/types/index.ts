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
  ClaimMatchers,
  TimingOptions,
  ValidatorConfig,
} from "./config.ts";

// Validation types
export type {
  ValidationErrorCode,
  ValidationError,
  ValidationWarningCode,
  ValidationWarning,
  ValidationSuccess,
  ValidationFailure,
  ValidationResult,
  FeatureCheckResult,
  ExpirationInfo,
} from "./validation.ts";
