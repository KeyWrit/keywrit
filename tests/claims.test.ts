/**
 * Tests for claim matchers
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp } from "./helpers.ts";

describe("claim matchers", () => {
  describe("issuer (iss)", () => {
    test("validates matching issuer", async () => {
      const token = await createToken({
        iss: "mycompany",
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { iss: "mycompany" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects wrong issuer", async () => {
      const token = await createToken({
        iss: "wrongcompany",
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { iss: "mycompany" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("CLAIM_MISMATCH");
        expect(result.error.details?.claim).toBe("iss");
      }
    });

    test("rejects missing issuer when required", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { iss: "mycompany" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("CLAIM_MISMATCH");
      }
    });
  });

  describe("subject (sub)", () => {
    test("validates matching subject", async () => {
      const token = await createToken({
        sub: "user@example.com",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { sub: "user@example.com" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects wrong subject", async () => {
      const token = await createToken({
        sub: "other@example.com",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { sub: "user@example.com" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("CLAIM_MISMATCH");
        expect(result.error.details?.claim).toBe("sub");
      }
    });
  });

  describe("audience (aud)", () => {
    test("validates single audience", async () => {
      const token = await createToken({
        aud: "myapp",
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { aud: "myapp" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("validates audience array (token has array)", async () => {
      const token = await createToken({
        aud: ["app1", "app2", "app3"],
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { aud: "app2" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("validates audience array (matcher has array)", async () => {
      const token = await createToken({
        aud: "myapp",
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { aud: ["myapp", "otherapp"] },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects wrong audience", async () => {
      const token = await createToken({
        aud: "wrongapp",
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { aud: "myapp" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("CLAIM_MISMATCH");
        expect(result.error.details?.claim).toBe("aud");
      }
    });
  });

  describe("required flags", () => {
    test("validates when all required flags present", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export", "import", "api"],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredFlags: ["export", "api"] },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredFlags: ["export", "api"] },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredFlags: ["export"] },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredKind: "pro" },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredKind: "pro" },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredKind: "pro" },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredFeatures: ["maxUsers", "region"] },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredFeatures: ["maxUsers", "region"] },
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

      const validator = await LicenseValidator.create({
        publicKey: publicKeyHex,
        claims: { requiredFeatures: ["maxUsers"] },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("MISSING_REQUIRED_FEATURE");
      }
    });
  });
});
