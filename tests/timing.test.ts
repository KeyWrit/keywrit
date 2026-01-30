/**
 * Tests for timing claim validation
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp, pastTimestamp, TEST_REALM } from "./helpers.ts";

describe("timing validation", () => {
  describe("expiration (exp)", () => {
    test("accepts valid non-expired token", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects expired token", async () => {
      const token = await createToken({
        sub: "test",
        exp: pastTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("TOKEN_EXPIRED");
        expect(result.error.message).toContain("expired");
      }
    });

    test("requires expiration by default", async () => {
      const token = await createToken({ sub: "test" });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("EXPIRATION_REQUIRED");
      }
    });

    test("allows no expiration when configured", async () => {
      const token = await createToken({ sub: "test" });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        allowNoExpiration: true,
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.warnings?.some((w) => w.code === "NO_EXPIRATION")).toBe(true);
      }
    });

    test("warns when token is expiring soon", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600), // 1 hour (within 7 day warning threshold)
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.warnings?.some((w) => w.code === "EXPIRING_SOON")).toBe(true);
      }
    });
  });

  describe("not before (nbf)", () => {
    test("accepts token that is already valid", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(7200),
        nbf: pastTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects token not yet valid", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(7200),
        nbf: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("TOKEN_NOT_YET_VALID");
        expect(result.error.message).toContain("not valid");
      }
    });
  });

  describe("clock skew tolerance", () => {
    test("respects clock skew for expired tokens", async () => {
      const token = await createToken({
        sub: "test",
        exp: pastTimestamp(30), // Expired 30 seconds ago
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        timing: { clockSkew: 60 },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("respects clock skew for nbf", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(7200),
        nbf: futureTimestamp(30), // Valid in 30 seconds
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        timing: { clockSkew: 60 },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects when outside clock skew", async () => {
      const token = await createToken({
        sub: "test",
        exp: pastTimestamp(120), // Expired 2 minutes ago
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        timing: { clockSkew: 60 },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
    });
  });

  describe("custom current time", () => {
    test("uses custom current time for validation", async () => {
      const exp = 1700000000; // Fixed timestamp
      const token = await createToken({ sub: "test", exp });

      // Token should be valid when "current time" is before expiration
      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        timing: { currentTime: exp - 3600 },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });
  });
});
