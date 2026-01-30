/**
 * Tests for revocation list
 */

import { describe, test, expect, mock } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp, TEST_REALM } from "./helpers.ts";

describe("revocation", () => {
  describe("static revocation list", () => {
    test("rejects token with revoked jti", async () => {
      const token = await createToken({
        jti: "revoked-token-123",
        sub: "user@example.com",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        revocation: {
          jti: ["revoked-token-123", "other-revoked"],
        },
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("TOKEN_REVOKED");
        expect(result.error.details?.jti).toBe("revoked-token-123");
        expect(result.error.details?.reason).toBe("jti_revoked");
      }
    });

    test("rejects token with revoked subject", async () => {
      const token = await createToken({
        jti: "valid-token",
        sub: "banned@example.com",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        revocation: {
          sub: ["banned@example.com"],
        },
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("TOKEN_REVOKED");
        expect(result.error.details?.sub).toBe("banned@example.com");
        expect(result.error.details?.reason).toBe("sub_revoked");
      }
    });

    test("allows token not in revocation list", async () => {
      const token = await createToken({
        jti: "valid-token",
        sub: "user@example.com",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        revocation: {
          jti: ["other-token"],
          sub: ["other@example.com"],
        },
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(true);
    });

    test("allows token when revocation list is empty", async () => {
      const token = await createToken({
        jti: "valid-token",
        sub: "user@example.com",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        revocation: {},
      });

      const result = await validator.validate(token);
      expect(result.valid).toBe(true);
    });
  });

  describe("static key with URL revocation", () => {
    test("fetches revocation list from URL with static public key", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mock(async (url: string) => {
        if (url === "https://example.com/revocation.json") {
          return new Response(
            JSON.stringify({ jti: ["revoked-token"] }),
            { status: 200 }
          );
        }
        return originalFetch(url);
      }) as typeof fetch;

      try {
        const token = await createToken({
          jti: "revoked-token",
          sub: "user@example.com",
          exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
          publicKey: publicKeyHex,
          revocationUrl: "https://example.com/revocation.json",
        });

        const result = await validator.validate(token);
        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.error.code).toBe("TOKEN_REVOKED");
        }
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    test("allows valid token with static key and URL revocation", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mock(async (url: string) => {
        if (url === "https://example.com/revocation.json") {
          return new Response(
            JSON.stringify({ jti: ["other-token"] }),
            { status: 200 }
          );
        }
        return originalFetch(url);
      }) as typeof fetch;

      try {
        const token = await createToken({
          jti: "valid-token",
          sub: "user@example.com",
          exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
          publicKey: publicKeyHex,
          revocationUrl: "https://example.com/revocation.json",
        });

        const result = await validator.validate(token);
        expect(result.valid).toBe(true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("URL-based revocation list", () => {
    test("fetches and checks revocation list from URL", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mock(async (url: string) => {
        if (url === "https://example.com/public-key") {
          return new Response(publicKeyHex, { status: 200 });
        }
        if (url === "https://example.com/revocation.json") {
          return new Response(
            JSON.stringify({ jti: ["revoked-via-url"] }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return originalFetch(url);
      }) as typeof fetch;

      try {
        const token = await createToken({
          jti: "revoked-via-url",
          sub: "user@example.com",
          exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
          publicKeyUrl: "https://example.com/public-key",
          revocationUrl: "https://example.com/revocation.json",
        });

        const result = await validator.validate(token);
        expect(result.valid).toBe(false);
        if (!result.valid) {
          expect(result.error.code).toBe("TOKEN_REVOKED");
        }
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    test("allows valid token when using revocation URL", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mock(async (url: string) => {
        if (url === "https://example.com/public-key") {
          return new Response(publicKeyHex, { status: 200 });
        }
        if (url === "https://example.com/revocation.json") {
          return new Response(
            JSON.stringify({ jti: ["other-token"] }),
            { status: 200 }
          );
        }
        return originalFetch(url);
      }) as typeof fetch;

      try {
        const token = await createToken({
          jti: "valid-token",
          sub: "user@example.com",
          exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
          publicKeyUrl: "https://example.com/public-key",
          revocationUrl: "https://example.com/revocation.json",
        });

        const result = await validator.validate(token);
        expect(result.valid).toBe(true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    test("continues validation when revocation URL fails", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mock(async (url: string) => {
        if (url === "https://example.com/public-key") {
          return new Response(publicKeyHex, { status: 200 });
        }
        if (url === "https://example.com/revocation.json") {
          return new Response("Server error", { status: 500 });
        }
        return originalFetch(url);
      }) as typeof fetch;

      try {
        const token = await createToken({
          jti: "valid-token",
          sub: "user@example.com",
          exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
          publicKeyUrl: "https://example.com/public-key",
          revocationUrl: "https://example.com/revocation.json",
        });

        const result = await validator.validate(token);
        expect(result.valid).toBe(true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    test("continues validation when revocation URL returns invalid JSON", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mock(async (url: string) => {
        if (url === "https://example.com/public-key") {
          return new Response(publicKeyHex, { status: 200 });
        }
        if (url === "https://example.com/revocation.json") {
          return new Response("not json", { status: 200 });
        }
        return originalFetch(url);
      }) as typeof fetch;

      try {
        const token = await createToken({
          jti: "valid-token",
          sub: "user@example.com",
          exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
          publicKeyUrl: "https://example.com/public-key",
          revocationUrl: "https://example.com/revocation.json",
        });

        const result = await validator.validate(token);
        expect(result.valid).toBe(true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    test("works without revocation URL", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mock(async (url: string) => {
        if (url === "https://example.com/public-key") {
          return new Response(publicKeyHex, { status: 200 });
        }
        return originalFetch(url);
      }) as typeof fetch;

      try {
        const token = await createToken({
          jti: "valid-token",
          sub: "user@example.com",
          exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
          publicKeyUrl: "https://example.com/public-key",
        });

        const result = await validator.validate(token);
        expect(result.valid).toBe(true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
