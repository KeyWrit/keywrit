/**
 * LicenseValidator - Main validation class
 */

import type {
  ValidatorConfig,
  ValidationResult,
  LicensePayload,
  FeatureCheckResult,
  ExpirationInfo,
  ValidationWarning,
} from "./types/index.ts";
import { decodeJWT, decodePayload } from "./jwt/decode.ts";
import { verifySignature } from "./jwt/verify.ts";
import { validateTimingClaims, validateClaimMatchers } from "./jwt/claims.ts";
import { normalizePublicKey } from "./utils/keys.ts";
import { now, formatDuration } from "./utils/time.ts";
import { malformedToken, invalidHeader, invalidPayload } from "./errors.ts";

/**
 * License validator for JWT-based license keys
 */
export class LicenseValidator<T = Record<string, unknown>> {
  private readonly publicKey: Uint8Array;
  private readonly config: ValidatorConfig;

  public constructor(config: ValidatorConfig) {
    this.publicKey = normalizePublicKey(config.publicKey);
    this.config = config;
  }

  /**
   * Validate a license token
   */
  public async validate(token: string): Promise<ValidationResult<T>> {
    // Decode the token
    const decodeResult = decodeJWT<T>(token);

    if (!decodeResult.success) {
      // Determine error type from decode error
      const errorMessage = decodeResult.error;
      let error;

      if (errorMessage.includes("structure")) {
        error = malformedToken(errorMessage);
      } else if (
        errorMessage.includes("algorithm") ||
        errorMessage.includes("type")
      ) {
        error = invalidHeader(errorMessage);
      } else if (
        errorMessage.includes("payload") ||
        errorMessage.includes("header")
      ) {
        error = invalidPayload(errorMessage);
      } else {
        error = malformedToken(errorMessage);
      }

      // Try to get unverified payload for debugging
      const unverifiedPayload = decodePayload(token) ?? undefined;

      return {
        valid: false,
        error,
        unverifiedPayload,
      };
    }

    const decoded = decodeResult.data;

    // Verify signature
    const verifyResult = await verifySignature(decoded, this.publicKey);

    if (!verifyResult.success) {
      return {
        valid: false,
        error: verifyResult.error,
        unverifiedPayload: decoded.payload as LicensePayload,
      };
    }

    // Collect all errors and warnings
    const allErrors: typeof verifyResult.error[] = [];
    const allWarnings: ValidationWarning[] = [];

    // Validate timing claims
    const timingResult = validateTimingClaims(
      decoded.payload,
      this.config.timing,
      this.config.allowNoExpiration
    );
    allErrors.push(...timingResult.errors);
    allWarnings.push(...timingResult.warnings);

    // Validate claim matchers
    if (this.config.claims) {
      const claimResult = validateClaimMatchers(
        decoded.payload,
        this.config.claims
      );
      allErrors.push(...claimResult.errors);
      allWarnings.push(...claimResult.warnings);
    }

    // Return failure if any errors
    if (allErrors.length > 0) {
      return {
        valid: false,
        error: allErrors[0]!,
        errors: allErrors.length > 1 ? allErrors : undefined,
        unverifiedPayload: decoded.payload as LicensePayload,
      };
    }

    // Success
    return {
      valid: true,
      license: decoded.payload,
      warnings: allWarnings.length > 0 ? allWarnings : undefined,
    };
  }

  /**
   * Synchronous validation (limited - signature verification is async)
   * Note: This method validates everything except the signature synchronously,
   * then performs async signature verification.
   */
  public validateSync(token: string): ValidationResult<T> {
    // For true sync operation, we'd need sync crypto
    // Currently this is a shim that throws
    throw new Error(
      "Synchronous validation not available. Use validate() instead."
    );
  }

  /**
   * Check if a feature is enabled in the license
   */
  public async hasFeature(token: string, feature: string): Promise<FeatureCheckResult> {
    const result = await this.validate(token);

    if (!result.valid) {
      const reason =
        result.error.code === "TOKEN_EXPIRED" ? "expired" : "invalid_token";
      return { enabled: false, reason };
    }

    const features = result.license.features ?? [];
    if (features.includes(feature)) {
      return { enabled: true };
    }

    return { enabled: false, reason: "not_in_license" };
  }

  /**
   * Check multiple features at once
   */
  public async hasFeatures(
    token: string,
    features: string[]
  ): Promise<Map<string, FeatureCheckResult>> {
    const result = await this.validate(token);
    const results = new Map<string, FeatureCheckResult>();

    if (!result.valid) {
      const reason =
        result.error.code === "TOKEN_EXPIRED" ? "expired" : "invalid_token";
      for (const feature of features) {
        results.set(feature, { enabled: false, reason });
      }
      return results;
    }

    const licenseFeatures = result.license.features ?? [];
    for (const feature of features) {
      if (licenseFeatures.includes(feature)) {
        results.set(feature, { enabled: true });
      } else {
        results.set(feature, { enabled: false, reason: "not_in_license" });
      }
    }

    return results;
  }

  /**
   * Get the tier from a license token
   */
  public async getTier(token: string): Promise<string | null> {
    const result = await this.validate(token);
    if (!result.valid) {
      return null;
    }
    return result.license.tier ?? null;
  }

  /**
   * Check if the license has at least the minimum tier
   */
  public async hasTier(token: string, minimumTier: string): Promise<boolean> {
    const result = await this.validate(token);
    if (!result.valid) {
      return false;
    }

    const hierarchy = this.config.claims?.tierHierarchy ?? [
      "free",
      "pro",
      "enterprise",
    ];
    const minimumIndex = hierarchy.indexOf(minimumTier);
    const actualTier = result.license.tier;
    const actualIndex = actualTier ? hierarchy.indexOf(actualTier) : -1;

    if (minimumIndex === -1 || actualIndex === -1) {
      return false;
    }

    return actualIndex >= minimumIndex;
  }

  /**
   * Create a new validator with extended configuration
   */
  public extend(config: Partial<ValidatorConfig>): LicenseValidator<T> {
    return new LicenseValidator({
      ...this.config,
      ...config,
      publicKey: config.publicKey
        ? config.publicKey
        : this.config.publicKey,
      claims: config.claims
        ? { ...this.config.claims, ...config.claims }
        : this.config.claims,
      timing: config.timing
        ? { ...this.config.timing, ...config.timing }
        : this.config.timing,
    });
  }

  /**
   * Get expiration information from a token (without full validation)
   */
  public getExpirationInfo(token: string): ExpirationInfo | null {
    const payload = decodePayload(token);
    if (!payload) {
      return null;
    }

    const currentTime = this.config.timing?.currentTime ?? now();
    const exp = payload.exp;

    if (exp === undefined) {
      return {
        expiresAt: null,
        isExpired: false,
        secondsRemaining: null,
        timeRemaining: null,
      };
    }

    const secondsRemaining = exp - currentTime;
    const isExpired = secondsRemaining <= 0;

    return {
      expiresAt: exp,
      isExpired,
      secondsRemaining,
      timeRemaining: formatDuration(Math.abs(secondsRemaining)),
    };
  }
}
