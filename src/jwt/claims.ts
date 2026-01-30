/**
 * JWT claim validation
 */

import type {
  LicensePayload,
  TimingOptions,
  ValidationError,
  ValidationWarning,
} from "../types/index.ts";
import {
  now,
  isPast,
  isFuture,
  isExpiringSoon,
  formatDuration,
  DEFAULT_CLOCK_SKEW,
} from "../utils/time.ts";

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
 * Validate timing claims (exp, nbf, iat)
 */
export function validateTimingClaims(
  payload: LicensePayload,
  options: TimingOptions = {},
  allowNoExpiration = false
): ClaimValidationResult {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  const clockSkew = options.clockSkew ?? DEFAULT_CLOCK_SKEW;
  const currentTime = options.currentTime ?? now();

  // Check expiration
  if (payload.exp !== undefined) {
    if (isPast(payload.exp, currentTime, clockSkew)) {
      const expiredAgo = currentTime - payload.exp;
      errors.push({
        code: "TOKEN_EXPIRED",
        message: `Token expired ${formatDuration(expiredAgo)} ago`,
        details: {
          exp: payload.exp,
          currentTime,
          expiredAt: new Date(payload.exp * 1000).toISOString(),
        },
      });
    } else if (isExpiringSoon(payload.exp, currentTime)) {
      const remaining = payload.exp - currentTime;
      warnings.push({
        code: "EXPIRING_SOON",
        message: `Token expires in ${formatDuration(remaining)}`,
        details: {
          exp: payload.exp,
          secondsRemaining: remaining,
        },
      });
    }

    // Check if clock skew was applied
    if (clockSkew > 0 && payload.exp < currentTime && payload.exp >= currentTime - clockSkew) {
      warnings.push({
        code: "CLOCK_SKEW_APPLIED",
        message: `Token accepted within clock skew tolerance (${clockSkew}s)`,
        details: { clockSkew },
      });
    }
  } else if (!allowNoExpiration) {
    errors.push({
      code: "EXPIRATION_REQUIRED",
      message: "Token must have an expiration time",
    });
  } else {
    warnings.push({
      code: "NO_EXPIRATION",
      message: "Token has no expiration time",
    });
  }

  // Check not-before
  if (payload.nbf !== undefined) {
    if (isFuture(payload.nbf, currentTime, clockSkew)) {
      const startsIn = payload.nbf - currentTime;
      errors.push({
        code: "TOKEN_NOT_YET_VALID",
        message: `Token not valid for another ${formatDuration(startsIn)}`,
        details: {
          nbf: payload.nbf,
          currentTime,
          validFrom: new Date(payload.nbf * 1000).toISOString(),
        },
      });
    }
  }

  return { errors, warnings };
}

/**
 * Validate claim matchers (flags, kind, features)
 */
export function validateClaimMatchers(
  payload: LicensePayload,
  options: ClaimMatcherOptions
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
