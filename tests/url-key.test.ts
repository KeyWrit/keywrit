/**
 * Tests for public key URL fetching
 */

import { describe, test, expect, mock } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp } from "./helpers.ts";

describe("public key from URL", () => {
  test("creates validator from URL", async () => {
    // Mock fetch to return the public key
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async (url: string) => {
      if (url === "https://example.com/public-key") {
        return new Response(publicKeyHex, { status: 200 });
      }
      return new Response("Not found", { status: 404 });
    }) as typeof fetch;

    try {
      const validator = await LicenseValidator.create({
        publicKeyUrl: "https://example.com/public-key",
      });

      const token = await createToken({
        sub: "test-user",
        exp: futureTimestamp(3600),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("handles whitespace in fetched key", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => {
      return new Response(`  ${publicKeyHex}  \n`, { status: 200 });
    }) as typeof fetch;

    try {
      const validator = await LicenseValidator.create({
        publicKeyUrl: "https://example.com/public-key",
      });

      const token = await createToken({
        sub: "test-user",
        exp: futureTimestamp(3600),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("throws on fetch failure", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => {
      return new Response("Not found", { status: 404, statusText: "Not Found" });
    }) as typeof fetch;

    try {
      await expect(
        LicenseValidator.create({
          publicKeyUrl: "https://example.com/missing-key",
        })
      ).rejects.toThrow("Failed to fetch public key");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("passes claim matchers from URL config", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => {
      return new Response(publicKeyHex, { status: 200 });
    }) as typeof fetch;

    try {
      const validator = await LicenseValidator.create({
        publicKeyUrl: "https://example.com/public-key",
        claims: { iss: "mycompany" },
      });

      const token = await createToken({
        iss: "wrongcompany",
        sub: "test-user",
        exp: futureTimestamp(3600),
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("CLAIM_MISMATCH");
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
