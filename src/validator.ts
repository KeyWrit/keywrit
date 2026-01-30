/**
 * LicenseValidator - Main validation class
 */

import type {
  ValidatorConfig,
  RevocationList,
  ValidationResult,
  ValidationError,
  LicensePayload,
  FlagCheckResult,
  ExpirationInfo,
  ValidationWarning,
  DomainCheckResult,
} from "./types/index.ts";
import { decodeJWT, decodePayload } from "./jwt/decode.ts";
import { verifySignature } from "./jwt/verify.ts";
import { validateTimingClaims, validateClaimMatchers } from "./jwt/claims.ts";
import { validateInternalClaims } from "./jwt/internal-claims.ts";
import { normalizePublicKey } from "./utils/keys.ts";
import { now, formatDuration } from "./utils/time.ts";
import { malformedToken, invalidHeader, invalidPayload } from "./errors.ts";

/**
 * Check if a hostname matches a domain pattern.
 * Supports wildcards: "*.example.org" matches "foo.example.org", "bar.baz.example.org"
 */
function matchesDomain(hostname: string, pattern: string): boolean {
  const normalizedHost = hostname.toLowerCase();
  const normalizedPattern = pattern.toLowerCase();

  if (normalizedHost === normalizedPattern) {
    return true;
  }

  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(1); // ".example.org"
    if (normalizedHost.endsWith(suffix) && normalizedHost.length > suffix.length) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a hostname is allowed by any of the domain patterns.
 */
function isDomainAllowed(hostname: string, allowedDomains: string[]): boolean {
  if (allowedDomains.length === 0) {
    return false;
  }
  return allowedDomains.some((pattern) => matchesDomain(hostname, pattern));
}

/**
 * License validator for JWT-based license keys
 */
export class LicenseValidator<T = Record<string, unknown>> {
  private readonly publicKey: Uint8Array;
  private readonly revocationUrl?: string;
  private readonly revocation?: RevocationList;
  private readonly realm: string;
  private readonly requiredFlags?: string[];
  private readonly requiredKind?: string;
  private readonly requiredFeatures?: string[];
  private readonly timing?: ValidatorConfig["timing"];
  private readonly allowNoExpiration?: boolean;

  private constructor(
    publicKey: Uint8Array,
    config: ValidatorConfig
  ) {
    this.publicKey = publicKey;
    this.revocationUrl = "revocationUrl" in config ? config.revocationUrl : undefined;
    this.revocation = "revocation" in config ? config.revocation : undefined;
    this.realm = config.realm;
    this.requiredFlags = config.requiredFlags;
    this.requiredKind = config.requiredKind;
    this.requiredFeatures = config.requiredFeatures;
    this.timing = config.timing;
    this.allowNoExpiration = config.allowNoExpiration;
  }

  /**
   * Create a validator from configuration
   */
  public static async create<T = Record<string, unknown>>(
    config: ValidatorConfig
  ): Promise<LicenseValidator<T>> {
    let publicKey: Uint8Array;

    if ("publicKey" in config && config.publicKey) {
      publicKey = normalizePublicKey(config.publicKey);
    } else if ("publicKeyUrl" in config && config.publicKeyUrl) {
      const response = await fetch(config.publicKeyUrl);
      if (!response.ok) {
        throw new Error(
          `Failed to fetch public key from ${config.publicKeyUrl}: ${response.status} ${response.statusText}`
        );
      }
      const keyText = (await response.text()).trim();
      publicKey = normalizePublicKey(keyText);
    } else {
      throw new Error("Either publicKey or publicKeyUrl must be provided");
    }

    return new LicenseValidator<T>(publicKey, config);
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
      decoded as import("./types/index.ts").DecodedJWT,
      this.publicKey
    );

    if (!verifyResult.success) {
      return {
        valid: false,
        error: verifyResult.error,
        unverifiedPayload: decoded.payload as LicensePayload,
      };
    }

    // Check revocation
    const revocationResult = await this.checkRevocation(decoded.payload as LicensePayload);
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
      this.realm
    );
    allErrors.push(...internalResult.errors);

    // Validate timing claims
    const timingResult = validateTimingClaims(
      decoded.payload as LicensePayload,
      this.timing,
      this.allowNoExpiration
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
      }
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
   * Get the license payload if valid, null otherwise
   */
  public async getLicense(token: string): Promise<LicensePayload<T> | null> {
    const result = await this.validate(token);
    if (!result.valid) {
      return null;
    }
    return result.license;
  }

  /**
   * Check if a flag is enabled in the license
   */
  public async hasFlag(token: string, flag: string): Promise<FlagCheckResult> {
    const result = await this.validate(token);

    if (!result.valid) {
      const reason =
        result.error.code === "TOKEN_EXPIRED" ? "expired" : "invalid_token";
      return { enabled: false, reason };
    }

    const flags = result.license.flags ?? [];
    if (flags.includes(flag)) {
      return { enabled: true };
    }

    return { enabled: false, reason: "not_in_license" };
  }

  /**
   * Check multiple flags at once
   */
  public async hasFlags(
    token: string,
    flags: string[]
  ): Promise<Map<string, FlagCheckResult>> {
    const result = await this.validate(token);
    const results = new Map<string, FlagCheckResult>();

    if (!result.valid) {
      const reason =
        result.error.code === "TOKEN_EXPIRED" ? "expired" : "invalid_token";
      for (const flag of flags) {
        results.set(flag, { enabled: false, reason });
      }
      return results;
    }

    const licenseFlags = result.license.flags ?? [];
    for (const flag of flags) {
      if (licenseFlags.includes(flag)) {
        results.set(flag, { enabled: true });
      } else {
        results.set(flag, { enabled: false, reason: "not_in_license" });
      }
    }

    return results;
  }

  /**
   * Get the kind from a license token
   */
  public async getKind(token: string): Promise<string | null> {
    const result = await this.validate(token);
    if (!result.valid) {
      return null;
    }
    return result.license.kind ?? null;
  }

  /**
   * Check if the license has the specified kind (exact match)
   */
  public async hasKind(token: string, kind: string): Promise<boolean> {
    const result = await this.validate(token);
    if (!result.valid) {
      return false;
    }
    return result.license.kind === kind;
  }

  /**
   * Get a feature value from the license features map
   */
  public async getFeature<V = unknown>(
    token: string,
    feature: string
  ): Promise<V | null> {
    const result = await this.validate(token);
    if (!result.valid) {
      return null;
    }
    const features = result.license.features ?? {};
    if (feature in features) {
      return features[feature] as V;
    }
    return null;
  }

  /**
   * Check if a feature exists in the license features map
   */
  public async hasFeature(token: string, feature: string): Promise<boolean> {
    const result = await this.validate(token);
    if (!result.valid) {
      return false;
    }
    const features = result.license.features ?? {};
    return feature in features;
  }

  /**
   * Check if a hostname is allowed by the license's allowedDomains.
   * Use this in browser environments to verify the current domain is permitted.
   *
   * @param token - The license token
   * @param hostname - The hostname to check (e.g., window.location.hostname)
   * @returns DomainCheckResult indicating if the domain is allowed
   */
  public async checkDomain(
    token: string,
    hostname: string
  ): Promise<DomainCheckResult> {
    const result = await this.validate(token);

    if (!result.valid) {
      const reason =
        result.error.code === "TOKEN_EXPIRED" ? "expired" : "invalid_token";
      return { allowed: false, reason };
    }

    const allowedDomains = result.license.allowedDomains;

    // If allowedDomains is not set, no domain restrictions apply
    if (allowedDomains === undefined) {
      return { allowed: true, reason: "no_restrictions" };
    }

    // Empty array means no domains are allowed
    if (allowedDomains.length === 0) {
      return { allowed: false, reason: "empty_allowlist" };
    }

    // Check if hostname matches any allowed pattern
    if (isDomainAllowed(hostname, allowedDomains)) {
      return { allowed: true };
    }

    return { allowed: false, reason: "domain_not_in_list" };
  }

  /**
   * Get the allowed domains from a license token
   * Returns undefined if no domain restrictions, empty array if no domains allowed
   */
  public async getAllowedDomains(token: string): Promise<string[] | undefined> {
    const result = await this.validate(token);
    if (!result.valid) {
      return undefined;
    }
    return result.license.allowedDomains;
  }

  /**
   * Get expiration information from a token (without full validation)
   */
  public getExpirationInfo(token: string): ExpirationInfo | null {
    const payload = decodePayload(token);
    if (!payload) {
      return null;
    }

    const currentTime = this.timing?.currentTime ?? now();
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

  /**
   * Check if a token is revoked
   */
  private async checkRevocation(
    payload: LicensePayload
  ): Promise<{ code: "TOKEN_REVOKED"; message: string; details?: Record<string, unknown> } | null> {
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
  private async fetchRevocationList(): Promise<RevocationList | null> {
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
}
