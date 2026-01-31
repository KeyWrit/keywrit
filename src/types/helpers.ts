/**
 * Helper type definitions for validation utilities
 */

/** Result of a flag check */
export interface FlagCheckResult {
    enabled: boolean;
    /** Reason if not enabled */
    reason?: "not_in_license" | "invalid_token" | "expired";
}

/** Information about token expiration */
export interface ExpirationInfo {
    /** Expiration timestamp (null if no expiration) */
    expiresAt: number | null;
    /** Whether the token is currently expired */
    isExpired: boolean;
    /** Seconds until expiration (negative if expired, null if no expiration) */
    secondsRemaining: number | null;
    /** Human-readable time until expiration */
    timeRemaining: string | null;
}

/** Result of a domain check */
export interface DomainCheckResult {
    allowed: boolean;
    /** Reason if not allowed */
    reason?:
        | "domain_not_in_list"
        | "empty_allowlist"
        | "no_restrictions"
        | "invalid_token"
        | "expired";
}
