/**
 * Validation result type definitions
 */

import type { ValidationError } from "./errors.ts";
import type { LicensePayload } from "./jwt.ts";
import type { ValidationWarning } from "./warnings.ts";

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
