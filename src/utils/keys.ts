/**
 * Key normalization utilities
 */

import type { PublicKeyInput } from "../types/index.ts";

/** Expected length of Ed25519 public key in bytes */
export const ED25519_PUBLIC_KEY_LENGTH = 32;

/**
 * Normalize public key input to Uint8Array
 * Accepts:
 * - Uint8Array (32 bytes)
 * - Hex string (64 characters)
 * - Base64 string
 * - Base64URL string
 */
export function normalizePublicKey(input: PublicKeyInput): Uint8Array {
    if (input instanceof Uint8Array) {
        if (input.length !== ED25519_PUBLIC_KEY_LENGTH) {
            throw new Error(
                `Invalid public key length: expected ${ED25519_PUBLIC_KEY_LENGTH} bytes, got ${input.length}`,
            );
        }
        return input;
    }

    if (typeof input === "string") {
        // Try hex first (64 hex chars = 32 bytes)
        if (/^[0-9a-fA-F]{64}$/.test(input)) {
            return hexToBytes(input);
        }

        // Try base64/base64url
        try {
            const bytes = base64ToBytes(input);
            if (bytes.length !== ED25519_PUBLIC_KEY_LENGTH) {
                throw new Error(
                    `Invalid public key length: expected ${ED25519_PUBLIC_KEY_LENGTH} bytes, got ${bytes.length}`,
                );
            }
            return bytes;
        } catch {
            throw new Error(
                "Invalid public key format: expected hex string (64 chars), base64, or Uint8Array (32 bytes)",
            );
        }
    }

    throw new Error("Invalid public key type: expected string or Uint8Array");
}

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Convert base64/base64url string to bytes
 */
function base64ToBytes(str: string): Uint8Array {
    // Normalize to standard base64
    let base64 = str.replace(/-/g, "+").replace(/_/g, "/");

    // Add padding if needed
    while (base64.length % 4 !== 0) {
        base64 += "=";
    }

    // Decode
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
