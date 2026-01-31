/**
 * LicenseValidatorBound - Token-bound validation with sync methods
 */

import type {
  ExpirationInfo,
  LicensePayload,
  ValidationError,
  ValidationResult,
  ValidatorConfig,
} from "../types";
import { isDomainAllowed as checkDomainMatch } from "../utils/domain.ts";
import { computeExpirationInfo } from "../utils/time.ts";
import { LicenseValidator } from "./base.ts";
import { LicenseValidatorUnbound } from "./unbound.ts";

/**
 * Bound license validator - pre-validated token with sync access.
 * All methods operate on the bound token synchronously.
 */
export class LicenseValidatorBound<
  T = Record<string, unknown>,
> extends LicenseValidator<T> {
  private readonly token: string;
  private readonly result: ValidationResult<T>;

  /** @internal */
  public constructor(
    realm: string,
    publicKey: Uint8Array,
    config: ValidatorConfig,
    token: string,
    result: ValidationResult<T>,
  ) {
    super(realm, publicKey, config);
    this.token = token;
    this.result = result;
  }

  /**
   * Whether the bound token is valid
   */
  public get valid(): boolean {
    return this.result.valid;
  }

  /**
   * Get the full validation result
   */
  public getResult(): ValidationResult<T> {
    return this.result;
  }

  /**
   * Get the license payload.
   * @throws Error if the token is invalid
   */
  public get payload(): LicensePayload<T> {
    if (!this.result.valid) {
      throw new Error(`Cannot access payload: ${this.result.error.message}`);
    }
    return this.result.license;
  }

  /**
   * Get the validation error if the token is invalid, null otherwise
   */
  public get error(): ValidationError | null {
    if (this.result.valid) {
      return null;
    }
    return this.result.error;
  }

  /**
   * Check if a flag is enabled in the license
   */
  public hasFlag(flag: string): boolean {
    if (!this.result.valid) {
      return false;
    }
    const flags = this.result.license.flags ?? [];
    return flags.includes(flag);
  }

  /**
   * Check multiple flags at once
   */
  public hasFlags(flags: string[]): Map<string, boolean> {
    const results = new Map<string, boolean>();

    if (!this.result.valid) {
      for (const flag of flags) {
        results.set(flag, false);
      }
      return results;
    }

    const licenseFlags = this.result.license.flags ?? [];
    for (const flag of flags) {
      results.set(flag, licenseFlags.includes(flag));
    }

    return results;
  }

  /**
   * Get the kind from the license
   */
  public getKind(): string | null {
    if (!this.result.valid) {
      return null;
    }
    return this.result.license.kind ?? null;
  }

  /**
   * Check if the license has the specified kind (exact match)
   */
  public hasKind(kind: string): boolean {
    if (!this.result.valid) {
      return false;
    }
    return this.result.license.kind === kind;
  }

  /**
   * Get a feature value from the license features map
   */
  public getFeature<V = unknown>(feature: string): V | null {
    if (!this.result.valid) {
      return null;
    }
    const features = this.result.license.features ?? {};
    if (feature in features) {
      return features[feature] as V;
    }
    return null;
  }

  /**
   * Check if a feature exists in the license features map
   */
  public hasFeature(feature: string): boolean {
    if (!this.result.valid) {
      return false;
    }
    const features = this.result.license.features ?? {};
    return feature in features;
  }

  /**
   * Check if a hostname is allowed by the license's allowedDomains.
   * Returns false for invalid tokens or if domain is not in the allowlist.
   * Returns true if no domain restrictions exist or domain matches.
   */
  public isDomainAllowed(hostname: string): boolean {
    if (!this.result.valid) {
      return false;
    }

    const allowedDomains = this.result.license.allowedDomains;

    // If allowedDomains is not set, no domain restrictions apply
    if (allowedDomains === undefined) {
      return true;
    }

    // Check if hostname matches any allowed pattern (handles empty array case)
    return checkDomainMatch(hostname, allowedDomains);
  }

  /**
   * Get the allowed domains from the license
   * Returns undefined if no domain restrictions, empty array if no domains allowed
   */
  public getAllowedDomains(): string[] | undefined {
    if (!this.result.valid) {
      return undefined;
    }
    return this.result.license.allowedDomains;
  }

  /**
   * Get expiration information from the bound token
   */
  public getExpirationInfo(): ExpirationInfo | null {
    if (!this.result.valid) {
      return null;
    }
    return computeExpirationInfo(
      this.result.license.exp,
      this.timing?.currentTime,
    );
  }

  /**
   * Re-validate the bound token.
   * Useful when time has passed and you need to check expiration again.
   * Returns a new bound validator with fresh validation results.
   */
  public async revalidate(): Promise<LicenseValidatorBound<T>> {
    const result = await this.performValidation(this.token);
    return new LicenseValidatorBound<T>(
      this.realm,
      this.publicKey,
      this.buildConfig(),
      this.token,
      result,
    );
  }

  /**
   * Unbind this validator, returning an unbound validator.
   * Useful when you need to validate different tokens with the same configuration.
   */
  public unbind(): LicenseValidatorUnbound<T> {
    return new LicenseValidatorUnbound<T>(
      this.realm,
      this.publicKey,
      this.buildConfig(),
    );
  }
}
