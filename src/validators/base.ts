/**
 * LicenseValidator - Abstract base class for license validation
 */

import { invalidHeader, invalidPayload, malformedToken } from "../errors.ts";
import { decodeJWT, decodePayload } from "../jwt/decode.ts";
import { verifySignature } from "../jwt/verify.ts";
import type {
  LicensePayload,
  RevocationList,
  ValidationError,
  ValidationResult,
  ValidationWarning,
  ValidatorConfig,
} from "../types/index.ts";
import { normalizePublicKey } from "../utils/keys.ts";
import type { LicenseValidatorBound } from "./bound.ts";
import { validateClaimMatchers, validateTimingClaims } from "./claims/index.ts";
import { validateInternalClaims } from "./claims/internal.ts";
import type { LicenseValidatorUnbound } from "./unbound.ts";

/**
 * Abstract base class for license validation.
 * Use static factory methods to create instances.
 */
export abstract class LicenseValidator<T = Record<string, unknown>> {
  protected readonly realm: string;
  protected readonly publicKey: Uint8Array;
  protected readonly revocationUrl?: string;
  protected readonly revocation?: RevocationList;
  protected readonly requiredFlags?: string[];
  protected readonly requiredKind?: string;
  protected readonly requiredFeatures?: string[];
  protected readonly timing?: ValidatorConfig["timing"];
  protected readonly allowNoExpiration?: boolean;

  protected constructor(
    realm: string,
    publicKey: Uint8Array,
    config: ValidatorConfig,
  ) {
    this.realm = realm;
    this.publicKey = publicKey;
    this.revocationUrl =
      "revocationUrl" in config ? config.revocationUrl : undefined;
    this.revocation = "revocation" in config ? config.revocation : undefined;
    this.requiredFlags = config.requiredFlags;
    this.requiredKind = config.requiredKind;
    this.requiredFeatures = config.requiredFeatures;
    this.timing = config.timing;
    this.allowNoExpiration = config.allowNoExpiration;
  }

  /**
   * Perform full validation of a license token.
   * This is the shared validation logic used by both bound and unbound validators.
   */
  protected async performValidation(
    token: string,
  ): Promise<ValidationResult<T>> {
    // Decode the token
    const decodeResult = decodeJWT<T>(token);

    if (!decodeResult.success) {
      // Determine error type from decode error
      const errorMessage = decodeResult.error;
      let error: ValidationError;

      if (errorMessage.includes("structure")) {
        error = malformedToken(errorMessage);
      } else if (
        errorMessage.includes("algorithm") ||
        errorMessage.includes("type") ||
        errorMessage.includes("version") ||
        errorMessage.includes("kwv")
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
    const verifyResult = await verifySignature(
      decoded as import("../types/index.ts").DecodedJWT,
      this.publicKey,
    );

    if (!verifyResult.success) {
      return {
        valid: false,
        error: verifyResult.error,
        unverifiedPayload: decoded.payload as LicensePayload,
      };
    }

    // Check revocation
    const revocationResult = await this.checkRevocation(
      decoded.payload as LicensePayload,
    );
    if (revocationResult) {
      return {
        valid: false,
        error: revocationResult,
        unverifiedPayload: decoded.payload as LicensePayload,
      };
    }

    // Collect all errors and warnings
    const allErrors: ValidationError[] = [];
    const allWarnings: ValidationWarning[] = [];

    // Validate internal claims (iss and aud)
    const internalResult = validateInternalClaims(
      decoded.payload as LicensePayload,
      this.realm,
    );
    allErrors.push(...internalResult.errors);

    // Validate timing claims
    const timingResult = validateTimingClaims(
      decoded.payload as LicensePayload,
      this.timing,
      this.allowNoExpiration,
    );
    allErrors.push(...timingResult.errors);
    allWarnings.push(...timingResult.warnings);

    // Validate claim matchers (flags, kind, features)
    const claimResult = validateClaimMatchers(
      decoded.payload as LicensePayload,
      {
        requiredFlags: this.requiredFlags,
        requiredKind: this.requiredKind,
        requiredFeatures: this.requiredFeatures,
      },
    );
    allErrors.push(...claimResult.errors);
    allWarnings.push(...claimResult.warnings);

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
   * Check if a token is revoked
   */
  protected async checkRevocation(payload: LicensePayload): Promise<{
    code: "TOKEN_REVOKED";
    message: string;
    details?: Record<string, unknown>;
  } | null> {
    // Get revocation list from static config or URL
    let revocationList: RevocationList | null = null;

    if (this.revocationUrl) {
      revocationList = await this.fetchRevocationList();
    } else if (this.revocation) {
      revocationList = this.revocation;
    }

    if (!revocationList) {
      return null;
    }

    // Check if jti is revoked
    if (payload.jti && revocationList.jti?.includes(payload.jti)) {
      return {
        code: "TOKEN_REVOKED",
        message: `Token has been revoked (jti: ${payload.jti})`,
        details: { jti: payload.jti, reason: "jti_revoked" },
      };
    }

    // Check if sub is revoked
    if (payload.sub && revocationList.sub?.includes(payload.sub)) {
      return {
        code: "TOKEN_REVOKED",
        message: `Subject has been revoked (sub: ${payload.sub})`,
        details: { sub: payload.sub, reason: "sub_revoked" },
      };
    }

    return null;
  }

  /**
   * Fetch revocation list from URL
   */
  protected async fetchRevocationList(): Promise<RevocationList | null> {
    if (!this.revocationUrl) {
      return null;
    }

    try {
      const response = await fetch(this.revocationUrl);
      if (!response.ok) {
        return null;
      }
      return (await response.json()) as RevocationList;
    } catch {
      return null;
    }
  }

  /**
   * Build a config object from the current validator's settings.
   * Used when creating bound validators from unbound ones.
   */
  protected buildConfig(): ValidatorConfig {
    const base = {
      requiredFlags: this.requiredFlags,
      requiredKind: this.requiredKind,
      requiredFeatures: this.requiredFeatures,
      timing: this.timing,
      allowNoExpiration: this.allowNoExpiration,
      publicKey: this.publicKey,
    };

    if (this.revocationUrl) {
      return { ...base, revocationUrl: this.revocationUrl };
    } else if (this.revocation) {
      return { ...base, revocation: this.revocation };
    }
    return base;
  }

  /**
   * Create an unbound validator for on-demand validation.
   * Returns a validator where methods require the token as a parameter.
   */
  public static async create<T = Record<string, unknown>>(
    realm: string,
    config: ValidatorConfig,
  ): Promise<LicenseValidatorUnbound<T>> {
    // Dynamic import to avoid circular dependency
    const { LicenseValidatorUnbound: Unbound } = await import("./unbound.ts");
    const publicKey = await resolvePublicKey(config);
    return new Unbound<T>(realm, publicKey, config);
  }

  /**
   * Create a bound validator with a pre-validated token.
   * Returns a validator with synchronous methods for accessing license data.
   */
  public static async createWithToken<T = Record<string, unknown>>(
    realm: string,
    config: ValidatorConfig,
    token: string,
  ): Promise<LicenseValidatorBound<T>> {
    const unbound = await LicenseValidator.create<T>(realm, config);
    return unbound.bind(token);
  }
}

/**
 * Resolve public key from config (either direct key or URL)
 */
export async function resolvePublicKey(
  config: ValidatorConfig,
): Promise<Uint8Array> {
  if ("publicKey" in config && config.publicKey) {
    return normalizePublicKey(config.publicKey);
  } else if ("publicKeyUrl" in config && config.publicKeyUrl) {
    const response = await fetch(config.publicKeyUrl);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch public key from ${config.publicKeyUrl}: ${response.status} ${response.statusText}`,
      );
    }
    const keyText = (await response.text()).trim();
    return normalizePublicKey(keyText);
  } else {
    throw new Error("Either publicKey or publicKeyUrl must be provided");
  }
}
