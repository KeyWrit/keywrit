/**
 * Validators barrel export
 */

export { LicenseValidator, resolvePublicKey } from "./base.ts";
export { LicenseValidatorBound } from "./bound.ts";
export type {
    ClaimMatcherOptions,
    ClaimValidationResult,
    InternalClaimValidationResult,
} from "./claims/index.ts";

// Re-export claims for internal use
export {
    validateClaimMatchers,
    validateInternalClaims,
    validateTimingClaims,
} from "./claims/index.ts";
export { LicenseValidatorUnbound } from "./unbound.ts";
