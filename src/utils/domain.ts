/**
 * Domain matching utilities for license validation
 */

/**
 * Check if a hostname matches a domain pattern.
 * Supports wildcards: "*.example.org" matches "foo.example.org", "bar.baz.example.org"
 */
export function matchesDomain(hostname: string, pattern: string): boolean {
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
export function isDomainAllowed(hostname: string, allowedDomains: string[]): boolean {
  if (allowedDomains.length === 0) {
    return false;
  }
  return allowedDomains.some((pattern) => matchesDomain(hostname, pattern));
}
