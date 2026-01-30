/**
 * Tests for claim matchers (flags, kind, features)
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp, TEST_REALM } from "./helpers.ts";

describe("claim matchers", () => {
  describe("required flags", () => {
    test("validates when all required flags present", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export", "import", "api"],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredFlags: ["export", "api"],
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects when missing required flag", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export"],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredFlags: ["export", "api"],
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("MISSING_REQUIRED_FLAG");
        expect(result.error.details?.requiredFlag).toBe("api");
      }
    });

    test("rejects when flags array is missing", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredFlags: ["export"],
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("MISSING_REQUIRED_FLAG");
      }
    });
  });

  describe("required kind", () => {
    test("validates when kind matches exactly", async () => {
      const token = await createToken({
        sub: "test",
        kind: "pro",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredKind: "pro",
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects when kind does not match", async () => {
      const token = await createToken({
        sub: "test",
        kind: "free",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredKind: "pro",
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("KIND_MISMATCH");
        expect(result.error.details?.requiredKind).toBe("pro");
        expect(result.error.details?.actualKind).toBe("free");
      }
    });

    test("rejects when kind is missing", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredKind: "pro",
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("KIND_MISMATCH");
      }
    });
  });

  describe("required features", () => {
    test("validates when all required features present", async () => {
      const token = await createToken({
        sub: "test",
        features: { maxUsers: 100, region: "us-west", customBranding: true },
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredFeatures: ["maxUsers", "region"],
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects when missing required feature", async () => {
      const token = await createToken({
        sub: "test",
        features: { maxUsers: 100 },
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredFeatures: ["maxUsers", "region"],
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("MISSING_REQUIRED_FEATURE");
        expect(result.error.details?.requiredFeature).toBe("region");
      }
    });

    test("rejects when features map is missing", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredFeatures: ["maxUsers"],
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("MISSING_REQUIRED_FEATURE");
      }
    });
  });
});
