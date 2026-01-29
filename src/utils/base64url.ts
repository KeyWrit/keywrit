/**
 * Base64URL encoding/decoding utilities
 * RFC 4648 Section 5: Base64 URL-safe alphabet
 */

const BASE64URL_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode bytes to base64url string (no padding)
 */
export function encode(data: Uint8Array): string {
  let result = "";
  const len = data.length;

  for (let i = 0; i < len; i += 3) {
    const b1 = data[i]!;
    const b2 = i + 1 < len ? data[i + 1]! : 0;
    const b3 = i + 2 < len ? data[i + 2]! : 0;

    const triplet = (b1 << 16) | (b2 << 8) | b3;

    result += BASE64URL_CHARS[(triplet >> 18) & 0x3f];
    result += BASE64URL_CHARS[(triplet >> 12) & 0x3f];

    if (i + 1 < len) {
      result += BASE64URL_CHARS[(triplet >> 6) & 0x3f];
    }
    if (i + 2 < len) {
      result += BASE64URL_CHARS[triplet & 0x3f];
    }
  }

  return result;
}

/**
 * Decode base64url string to bytes
 * Handles both padded and unpadded input
 */
export function decode(str: string): Uint8Array {
  // Remove padding if present
  str = str.replace(/=+$/, "");

  // Replace standard base64 chars with URL-safe ones (in case of mixed input)
  str = str.replace(/\+/g, "-").replace(/\//g, "_");

  const len = str.length;
  const outputLen = Math.floor((len * 3) / 4);
  const result = new Uint8Array(outputLen);

  let resultIndex = 0;
  let buffer = 0;
  let bits = 0;

  for (let i = 0; i < len; i++) {
    const char = str[i]!;
    const value = BASE64URL_CHARS.indexOf(char);

    if (value === -1) {
      throw new Error(`Invalid base64url character: ${char}`);
    }

    buffer = (buffer << 6) | value;
    bits += 6;

    if (bits >= 8) {
      bits -= 8;
      result[resultIndex++] = (buffer >> bits) & 0xff;
    }
  }

  return result.slice(0, resultIndex);
}

/**
 * Encode a UTF-8 string to base64url
 */
export function encodeString(str: string): string {
  const encoder = new TextEncoder();
  return encode(encoder.encode(str));
}

/**
 * Decode base64url to a UTF-8 string
 */
export function decodeString(str: string): string {
  const decoder = new TextDecoder();
  return decoder.decode(decode(str));
}
