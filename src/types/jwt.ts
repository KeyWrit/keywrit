/**
 * JWT-related type definitions
 */

/** JWT Header for EdDSA tokens */
export interface JWTHeader {
  alg: "EdDSA";
  typ: "JWT";
}

/** Standard JWT claims */
export interface StandardClaims {
  /** Issuer - who created the license */
  iss?: string;
  /** Subject - license holder */
  sub?: string;
  /** Audience - target application */
  aud?: string | string[];
  /** Expiration time (Unix timestamp) */
  exp?: number;
  /** Not before (Unix timestamp) */
  nbf?: number;
  /** Issued at (Unix timestamp) */
  iat?: number;
  /** JWT ID - unique identifier */
  jti?: string;
}

/** License-specific claims */
export interface LicenseClaims {
  /** License tier (e.g., "free", "pro", "enterprise") */
  tier?: string;
  /** Array of enabled feature flags */
  features?: string[];
  /** Number of allowed seats */
  seats?: number;
  /** Arbitrary metadata */
  meta?: Record<string, unknown>;
}

/** Complete license payload combining standard and license claims */
export type LicensePayload<T = Record<string, unknown>> = StandardClaims &
  LicenseClaims &
  T;

/** Decoded JWT structure */
export interface DecodedJWT<T = Record<string, unknown>> {
  header: JWTHeader;
  payload: LicensePayload<T>;
  signature: Uint8Array;
  /** Raw signing input (header.payload) for verification */
  signingInput: string;
}
