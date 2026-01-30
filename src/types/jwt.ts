/**
 * JWT-related type definitions
 */

/** JWT Header for EdDSA tokens */
export interface JWTHeader {
  alg: "EdDSA";
  typ: "JWT";
  /** KeyWrit version */
  kwv: number;
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
  /** License kind (e.g., "free", "pro", "enterprise") */
  kind?: string;
  /** Array of enabled flags */
  flags?: string[];
  /** Arbitrary features/metadata */
  features?: Record<string, unknown>;
  /**
   * Allowed domains for client-side usage.
   * Supports wildcards (e.g., "*.example.org" matches "foo.example.org").
   * If set to empty array, no domains are allowed.
   * If undefined, domain checking is not enforced.
   */
  allowedDomains?: string[];
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
