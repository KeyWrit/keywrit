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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

      const validator = new LicenseValidator({
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

  describe("required features", () => {
    test("validates when all required features present", async () => {
      const token = await createToken({
        sub: "test",
        features: ["export", "import", "api"],
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: { requiredFeatures: ["export", "api"] },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects when missing required feature", async () => {
      const token = await createToken({
        sub: "test",
        features: ["export"],
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: { requiredFeatures: ["export", "api"] },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("MISSING_REQUIRED_FEATURE");
        expect(result.error.details?.requiredFeature).toBe("api");
      }
    });

    test("rejects when features array is missing", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: { requiredFeatures: ["export"] },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("MISSING_REQUIRED_FEATURE");
      }
    });
  });

  describe("minimum tier", () => {
    test("validates when tier meets minimum (exact match)", async () => {
      const token = await createToken({
        sub: "test",
        tier: "pro",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: { minimumTier: "pro" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("validates when tier exceeds minimum", async () => {
      const token = await createToken({
        sub: "test",
        tier: "enterprise",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: { minimumTier: "pro" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects insufficient tier", async () => {
      const token = await createToken({
        sub: "test",
        tier: "free",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: { minimumTier: "pro" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INSUFFICIENT_TIER");
      }
    });

    test("uses custom tier hierarchy", async () => {
      const token = await createToken({
        sub: "test",
        tier: "gold",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: {
          minimumTier: "silver",
          tierHierarchy: ["bronze", "silver", "gold", "platinum"],
        },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects unknown tier", async () => {
      const token = await createToken({
        sub: "test",
        tier: "unknown",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: { minimumTier: "pro" },
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INSUFFICIENT_TIER");
      }
    });
  });
});
