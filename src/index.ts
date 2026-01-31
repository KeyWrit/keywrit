// Main validator classes
// LicenseValidator is exported as the main entry point with static factory methods

// Constants
export {
  KEYWRIT_ISSUER,
  KEYWRIT_VERSION,
  SUPPORTED_VERSIONS,
} from "./constants.ts";
// Utility functions
export { decode, decodePayload } from "./jwt/decode.ts";
// Types
export type {
  DecodedJWT,
  DomainCheckResult,
  ExpirationInfo,
  // Flag checking
  FlagCheckResult,
  // JWT structure
  JWTHeader,
  LicenseClaims,
  LicensePayload,
  // Configuration
  PublicKeyInput,
  RevocationList,
  StandardClaims,
  TimingOptions,
  ValidationError,
  ValidationErrorCode,
  ValidationFailure,
  // Validation results
  ValidationResult,
  ValidationSuccess,
  ValidationWarning,
  ValidationWarningCode,
  ValidatorConfig,
} from "./types/index.ts";
export {
  LicenseValidator,
  LicenseValidatorBound,
  LicenseValidatorUnbound,
} from "./validators/index.ts";

import type { ValidationResult, ValidatorConfig } from "./types/index.ts";
// One-shot validation function
import { LicenseValidator } from "./validators/index.ts";

/**
 * One-shot license validation
 *
 * @example
 * ```typescript
 * const result = await validateLicense('my-app', token, {
 *   publicKey: "d75a980182b10ab...",
 * });
 * ```
 */
export async function validateLicense<T = Record<string, unknown>>(
  realm: string,
  token: string,
  config: ValidatorConfig,
): Promise<ValidationResult<T>> {
  const validator = await LicenseValidator.create<T>(realm, config);
  return validator.validate(token);
}

/**
 * Create a validation function with pre-configured settings
 *
 * @example
 * ```typescript
 * const validate = await createValidator('my-app', {
 *   publicKey: "d75a980182b10ab...",
 * });
 *
 * const result = await validate(token);
 * ```
 */
export async function createValidator<T = Record<string, unknown>>(
  realm: string,
  config: ValidatorConfig,
): Promise<(token: string) => Promise<ValidationResult<T>>> {
  const validator = await LicenseValidator.create<T>(realm, config);
  return (token: string) => validator.validate(token);
}
