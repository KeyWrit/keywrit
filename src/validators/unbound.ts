/**
 * LicenseValidatorUnbound - On-demand validation with token as parameter
 */

import { decodePayload } from "../jwt/decode.ts";
import type {
  DomainCheckResult,
  ExpirationInfo,
  FlagCheckResult,
  LicensePayload,
  ValidationResult,
  ValidatorConfig,
} from "../types/index.ts";
import { isDomainAllowed } from "../utils/domain.ts";
import { computeExpirationInfo } from "../utils/time.ts";
import { LicenseValidator } from "./base.ts";
import { LicenseValidatorBound } from "./bound.ts";

/**
 * Unbound license validator - validates tokens on demand.
 * All methods require the token as a parameter.
 */
export class LicenseValidatorUnbound<
  T = Record<string, unknown>,
> extends LicenseValidator<T> {
  /** @internal */
  public constructor(
    realm: string,
    publicKey: Uint8Array,
    config: ValidatorConfig,
  ) {
    super(realm, publicKey, config);
  }

  /**
   * Validate a license token
   */
  public async validate(token: string): Promise<ValidationResult<T>> {
    return this.performValidation(token);
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
    flags: string[],
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
    feature: string,
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
    hostname: string,
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
    return computeExpirationInfo(payload.exp, this.timing?.currentTime);
  }

  /**
   * Bind this validator to a specific token.
   * Returns a bound validator with sync methods.
   */
  public async bind(token: string): Promise<LicenseValidatorBound<T>> {
    const result = await this.validate(token);
    return new LicenseValidatorBound<T>(
      this.realm,
      this.publicKey,
      this.buildConfig(),
      token,
      result,
    );
  }
}
