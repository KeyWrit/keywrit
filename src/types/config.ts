/**
 * Configuration type definitions
 */

/** Accepted formats for Ed25519 public keys */
export type PublicKeyInput = string | Uint8Array;

/** Timing options for validation */
export interface TimingOptions {
  /** Clock skew tolerance in seconds (default: 60) */
  clockSkew?: number;
  /** Custom current time for testing (Unix timestamp) */
  currentTime?: number;
}

/** Revocation list for invalidating tokens */
export interface RevocationList {
  /** Revoked JWT IDs (jti claim) */
  jti?: string[];
  /** Revoked subjects (sub claim) - all tokens for these subjects are invalid */
  sub?: string[];
}

/** Base validator configuration options */
export interface ValidatorConfigBase {
  /** Required flags that must be present in the flags array */
  requiredFlags?: string[];
  /** Required kind (exact match) */
  requiredKind?: string;
  /** Required feature keys that must be present in the features map */
  requiredFeatures?: string[];
  /** Timing options */
  timing?: TimingOptions;
  /** Allow tokens without expiration (default: false) */
  allowNoExpiration?: boolean;
}

/** Public key source - either direct key or URL */
export type PublicKeySource =
  | { publicKey: PublicKeyInput; publicKeyUrl?: never }
  | { publicKey?: never; publicKeyUrl: string };

/** Revocation source - either static list or URL (both optional) */
export type RevocationSource =
  | { revocation?: RevocationList; revocationUrl?: never }
  | { revocation?: never; revocationUrl?: string };

/** Validator configuration */
export type ValidatorConfig = ValidatorConfigBase & PublicKeySource & RevocationSource;
