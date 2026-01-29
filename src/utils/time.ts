/**
 * Time utilities for JWT validation
 */

/** Default clock skew tolerance in seconds */
export const DEFAULT_CLOCK_SKEW = 60;

/**
 * Get current Unix timestamp in seconds
 */
export function now(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Check if a timestamp is in the past (with optional clock skew)
 */
export function isPast(
  timestamp: number,
  currentTime?: number,
  clockSkew = 0
): boolean {
  const time = currentTime ?? now();
  return timestamp < time - clockSkew;
}

/**
 * Check if a timestamp is in the future (with optional clock skew)
 */
export function isFuture(
  timestamp: number,
  currentTime?: number,
  clockSkew = 0
): boolean {
  const time = currentTime ?? now();
  return timestamp > time + clockSkew;
}

/**
 * Format seconds into human-readable duration
 */
export function formatDuration(seconds: number): string {
  const absSeconds = Math.abs(seconds);

  if (absSeconds < 60) {
    return `${absSeconds} second${absSeconds !== 1 ? "s" : ""}`;
  }

  if (absSeconds < 3600) {
    const minutes = Math.floor(absSeconds / 60);
    return `${minutes} minute${minutes !== 1 ? "s" : ""}`;
  }

  if (absSeconds < 86400) {
    const hours = Math.floor(absSeconds / 3600);
    return `${hours} hour${hours !== 1 ? "s" : ""}`;
  }

  const days = Math.floor(absSeconds / 86400);
  return `${days} day${days !== 1 ? "s" : ""}`;
}

/** Threshold for "expiring soon" warning (7 days in seconds) */
export const EXPIRING_SOON_THRESHOLD = 7 * 24 * 60 * 60;

/**
 * Check if token is expiring soon
 */
export function isExpiringSoon(
  exp: number,
  currentTime?: number,
  threshold = EXPIRING_SOON_THRESHOLD
): boolean {
  const time = currentTime ?? now();
  const remaining = exp - time;
  return remaining > 0 && remaining <= threshold;
}
