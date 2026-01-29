/**
 * Configuration type definitions
 */

/** Accepted formats for Ed25519 public keys */
export type PublicKeyInput = string | Uint8Array;

/** Claim matchers for validation */
export interface ClaimMatchers {
  /** Expected issuer */
  iss?: string;
  /** Expected audience (can match any in array) */
  aud?: string | string[];
  /** Expected subject */
  sub?: string;
  /** Required features that must be present */
  requiredFeatures?: string[];
  /** Minimum required tier */
  minimumTier?: string;
  /** Tier hierarchy for comparison (lower index = lower tier) */
  tierHierarchy?: string[];
}

/** Timing options for validation */
export interface TimingOptions {
  /** Clock skew tolerance in seconds (default: 60) */
  clockSkew?: number;
  /** Custom current time for testing (Unix timestamp) */
  currentTime?: number;
}

/** Validator configuration */
export interface ValidatorConfig {
  /** Ed25519 public key for signature verification */
  publicKey: PublicKeyInput;
  /** Claim matchers for validation */
  claims?: ClaimMatchers;
  /** Timing options */
  timing?: TimingOptions;
  /** Allow tokens without expiration (default: false) */
  allowNoExpiration?: boolean;
}
