/**
 * Internal claim validation for KeyWrit-specific requirements
 */

import type { LicensePayload, ValidationError } from "../../types/index.ts";
import { KEYWRIT_ISSUER } from "../../constants.ts";

/** Result of internal claim validation */
export interface InternalClaimValidationResult {
  errors: ValidationError[];
}

/**
 * Validate internal KeyWrit claims (iss and aud)
 * These are required for all KeyWrit tokens
 */
export function validateInternalClaims(
  payload: LicensePayload,
  realm: string
): InternalClaimValidationResult {
  const errors: ValidationError[] = [];

  // Validate issuer is "keywrit"
  if (payload.iss !== KEYWRIT_ISSUER) {
    errors.push({
      code: "INVALID_ISSUER",
      message: `Invalid issuer: expected "${KEYWRIT_ISSUER}", got "${payload.iss ?? "(none)"}"`,
      details: {
        expected: KEYWRIT_ISSUER,
        actual: payload.iss,
      },
    });
  }

  // Validate audience contains the realm
  const actualAuds = payload.aud
    ? Array.isArray(payload.aud)
      ? payload.aud
      : [payload.aud]
    : [];

  if (!actualAuds.includes(realm)) {
    errors.push({
      code: "INVALID_AUDIENCE",
      message: `Token not authorized for this realm: expected audience to include "${realm}", got [${actualAuds.join(", ") || "(none)"}]`,
      details: {
        expectedRealm: realm,
        actualAudience: actualAuds,
      },
    });
  }

  return { errors };
}
