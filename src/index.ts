// Main validator class
export { LicenseValidator } from "./validator.ts";

// Constants
export {
  KEYWRIT_ISSUER,
  KEYWRIT_VERSION,
  SUPPORTED_VERSIONS,
} from "./constants.ts";

// Types
export type {
  // Configuration
  PublicKeyInput,
  ValidatorConfig,
  TimingOptions,
  RevocationList,
  // JWT structure
  JWTHeader,
  StandardClaims,
  LicenseClaims,
  LicensePayload,
  DecodedJWT,
  // Validation results
  ValidationResult,
  ValidationSuccess,
  ValidationFailure,
  ValidationError,
  ValidationErrorCode,
  ValidationWarning,
  ValidationWarningCode,
  // Flag checking
  FlagCheckResult,
  ExpirationInfo,
} from "./types/index.ts";

// Utility functions
export { decode, decodePayload } from "./jwt/decode.ts";

// One-shot validation function
import { LicenseValidator } from "./validator.ts";
import type { ValidatorConfig, ValidationResult } from "./types/index.ts";

/**
 * One-shot license validation
 *
 * @example
 * ```typescript
 * const result = await validateLicense(token, {
 *   publicKey: "d75a980182b10ab...",
 *   libraryId: "my-app"
 * });
 * ```
 */
export async function validateLicense<T = Record<string, unknown>>(
  token: string,
  config: ValidatorConfig
): Promise<ValidationResult<T>> {
  const validator = await LicenseValidator.create<T>(config);
  return validator.validate(token);
}

/**
 * Create a validation function with pre-configured settings
 *
 * @example
 * ```typescript
 * const validate = await createValidator({
 *   publicKey: "d75a980182b10ab...",
 *   libraryId: "my-app"
 * });
 *
 * const result = await validate(token);
 * ```
 */
export async function createValidator<T = Record<string, unknown>>(
  config: ValidatorConfig
): Promise<(token: string) => Promise<ValidationResult<T>>> {
  const validator = await LicenseValidator.create<T>(config);
  return (token: string) => validator.validate(token);
}
