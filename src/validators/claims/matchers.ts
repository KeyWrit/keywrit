/**
 * Claim matcher validation
 */

import type {
  LicensePayload,
  ValidationError,
  ValidationWarning,
} from "../../types/index.ts";

/** Result of claim validation */
export interface ClaimValidationResult {
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

/** Options for claim matcher validation */
export interface ClaimMatcherOptions {
  requiredFlags?: string[];
  requiredKind?: string;
  requiredFeatures?: string[];
}

/**
 * Validate claim matchers (flags, kind, features)
 */
export function validateClaimMatchers(
  payload: LicensePayload,
  options: ClaimMatcherOptions,
): ClaimValidationResult {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  // Check required flags
  if (options.requiredFlags && options.requiredFlags.length > 0) {
    const licenseFlags = payload.flags ?? [];
    for (const flag of options.requiredFlags) {
      if (!licenseFlags.includes(flag)) {
        errors.push({
          code: "MISSING_REQUIRED_FLAG",
          message: `Missing required flag: "${flag}"`,
          details: {
            requiredFlag: flag,
            availableFlags: licenseFlags,
          },
        });
      }
    }
  }

  // Check required kind (exact match)
  if (options.requiredKind !== undefined) {
    if (payload.kind !== options.requiredKind) {
      errors.push({
        code: "KIND_MISMATCH",
        message: `Kind mismatch: expected "${options.requiredKind}", got "${payload.kind ?? "(none)"}"`,
        details: {
          requiredKind: options.requiredKind,
          actualKind: payload.kind,
        },
      });
    }
  }

  // Check required features (keys in the features map)
  if (options.requiredFeatures && options.requiredFeatures.length > 0) {
    const licenseFeatures = payload.features ?? {};
    const availableKeys = Object.keys(licenseFeatures);
    for (const feature of options.requiredFeatures) {
      if (!(feature in licenseFeatures)) {
        errors.push({
          code: "MISSING_REQUIRED_FEATURE",
          message: `Missing required feature: "${feature}"`,
          details: {
            requiredFeature: feature,
            availableFeatures: availableKeys,
          },
        });
      }
    }
  }

  return { errors, warnings };
}
