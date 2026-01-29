/**
 * JWT claim validation
 */

import type {
  ClaimMatchers,
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
 * Validate claim matchers
 */
export function validateClaimMatchers(
  payload: LicensePayload,
  matchers: ClaimMatchers
): ClaimValidationResult {
  const errors: ValidationError[] = [];
  const warnings: ValidationWarning[] = [];

  // Check issuer
  if (matchers.iss !== undefined && payload.iss !== matchers.iss) {
    errors.push({
      code: "CLAIM_MISMATCH",
      message: `Issuer mismatch: expected "${matchers.iss}", got "${payload.iss ?? "(none)"}"`,
      details: { claim: "iss", expected: matchers.iss, actual: payload.iss },
    });
  }

  // Check subject
  if (matchers.sub !== undefined && payload.sub !== matchers.sub) {
    errors.push({
      code: "CLAIM_MISMATCH",
      message: `Subject mismatch: expected "${matchers.sub}", got "${payload.sub ?? "(none)"}"`,
      details: { claim: "sub", expected: matchers.sub, actual: payload.sub },
    });
  }

  // Check audience
  if (matchers.aud !== undefined) {
    const expectedAuds = Array.isArray(matchers.aud)
      ? matchers.aud
      : [matchers.aud];
    const actualAuds = payload.aud
      ? Array.isArray(payload.aud)
        ? payload.aud
        : [payload.aud]
      : [];

    const hasMatchingAud = expectedAuds.some((exp) => actualAuds.includes(exp));
    if (!hasMatchingAud) {
      errors.push({
        code: "CLAIM_MISMATCH",
        message: `Audience mismatch: expected one of [${expectedAuds.join(", ")}], got [${actualAuds.join(", ") || "(none)"}]`,
        details: { claim: "aud", expected: expectedAuds, actual: actualAuds },
      });
    }
  }

  // Check required features
  if (matchers.requiredFeatures && matchers.requiredFeatures.length > 0) {
    const licenseFeatures = payload.features ?? [];
    for (const feature of matchers.requiredFeatures) {
      if (!licenseFeatures.includes(feature)) {
        errors.push({
          code: "MISSING_REQUIRED_FEATURE",
          message: `Missing required feature: "${feature}"`,
          details: {
            requiredFeature: feature,
            availableFeatures: licenseFeatures,
          },
        });
      }
    }
  }

  // Check minimum tier
  if (matchers.minimumTier !== undefined) {
    const hierarchy = matchers.tierHierarchy ?? ["free", "pro", "enterprise"];
    const minimumIndex = hierarchy.indexOf(matchers.minimumTier);
    const actualIndex = payload.tier
      ? hierarchy.indexOf(payload.tier)
      : -1;

    if (minimumIndex === -1) {
      // Unknown minimum tier, skip validation
    } else if (actualIndex === -1) {
      errors.push({
        code: "INSUFFICIENT_TIER",
        message: `Unknown tier: "${payload.tier ?? "(none)"}"`,
        details: {
          minimumTier: matchers.minimumTier,
          actualTier: payload.tier,
          hierarchy,
        },
      });
    } else if (actualIndex < minimumIndex) {
      errors.push({
        code: "INSUFFICIENT_TIER",
        message: `Insufficient tier: requires "${matchers.minimumTier}", license has "${payload.tier}"`,
        details: {
          minimumTier: matchers.minimumTier,
          actualTier: payload.tier,
          hierarchy,
        },
      });
    }
  }

  return { errors, warnings };
}
