/**
 * Ed25519 signature verification wrapper
 * Uses @noble/ed25519 for cryptographic operations
 */

import { verifyAsync as nobleVerifyAsync } from "@noble/ed25519";

/**
 * Verify an Ed25519 signature
 *
 * @param signature - 64-byte signature
 * @param message - Message that was signed (as bytes)
 * @param publicKey - 32-byte public key
 * @returns Promise<boolean> - true if signature is valid
 */
export async function verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
): Promise<boolean> {
    try {
        return await nobleVerifyAsync(signature, message, publicKey);
    } catch {
        // Invalid signature format or other crypto errors
        return false;
    }
}

/**
 * Synchronous Ed25519 signature verification
 * Note: @noble/ed25519 v2+ requires SHA-512 to be configured for sync operations
 * This falls back to async internally
 */
export function verifySync(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
): boolean {
    // @noble/ed25519 v2+ async by default
    // For sync, we need to configure sha512Sync
    // Since we want to support both browser and Node, we'll use the sync import if available
    try {
        // Try sync verification if available
        const { verify: syncVerify } = require("@noble/ed25519");
        // The library may throw if sync is not configured
        return syncVerify(signature, message, publicKey) as boolean;
    } catch {
        // If sync fails, this is a configuration issue
        throw new Error(
            "Synchronous verification not available. Use async verify() instead.",
        );
    }
}
