/**
 * Tests for LicenseValidator class methods
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator, validateLicense, createValidator } from "../src/index.ts";
import { createToken, createRawToken, publicKey, publicKeyHex, futureTimestamp, TEST_REALM } from "./helpers.ts";

describe("LicenseValidator", () => {
  describe("getLicense", () => {
    test("returns license payload for valid token", async () => {
      const token = await createToken({
        sub: "user@example.com",
        kind: "pro",
        flags: ["export", "import"],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const license = await validator.getLicense(token);

      expect(license).not.toBeNull();
      expect(license?.sub).toBe("user@example.com");
      expect(license?.kind).toBe("pro");
      expect(license?.flags).toEqual(["export", "import"]);
    });

    test("returns null for invalid token", async () => {
      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const license = await validator.getLicense("invalid-token");

      expect(license).toBeNull();
    });

    test("returns null for expired token", async () => {
      const token = await createToken({
        sub: "test",
        exp: Math.floor(Date.now() / 1000) - 3600,
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const license = await validator.getLicense(token);

      expect(license).toBeNull();
    });
  });

  describe("multiple errors", () => {
    test("collects multiple validation errors", async () => {
      const token = await createToken({
        sub: "test",
        flags: [],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
        requiredFlags: ["flag1", "flag2"],
      });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        // First error
        expect(result.error).toBeDefined();
        // Additional errors
        expect(result.errors).toBeDefined();
        expect(result.errors!.length).toBeGreaterThan(0);
      }
    });
  });
});

describe("utility functions", () => {
  describe("validateLicense", () => {
    test("performs one-shot validation", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const result = await validateLicense(TEST_REALM, token, { publicKey: publicKeyHex });
      expect(result.valid).toBe(true);
    });

    test("accepts all validator options", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const result = await validateLicense(TEST_REALM, token, {
        publicKey: publicKeyHex,
        timing: { clockSkew: 30 },
      });
      expect(result.valid).toBe(true);
    });
  });

  describe("createValidator", () => {
    test("returns reusable validation function", async () => {
      const validate = await createValidator(TEST_REALM, { publicKey: publicKeyHex });

      const token1 = await createToken({ sub: "user1", exp: futureTimestamp(3600) });
      const token2 = await createToken({ sub: "user2", exp: futureTimestamp(3600) });

      const result1 = await validate(token1);
      const result2 = await validate(token2);

      expect(result1.valid).toBe(true);
      expect(result2.valid).toBe(true);
      if (result1.valid && result2.valid) {
        expect(result1.license.sub).toBe("user1");
        expect(result2.license.sub).toBe("user2");
      }
    });
  });
});

describe("public key formats", () => {
  test("accepts Uint8Array", async () => {
    const token = await createToken({
      sub: "test",
      exp: futureTimestamp(3600),
    });

    const validator = await LicenseValidator.create(TEST_REALM, { publicKey });
    const result = await validator.validate(token);

    expect(result.valid).toBe(true);
  });

  test("accepts hex string", async () => {
    const token = await createToken({
      sub: "test",
      exp: futureTimestamp(3600),
    });

    const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
    const result = await validator.validate(token);

    expect(result.valid).toBe(true);
  });

  test("accepts base64 string", async () => {
    const token = await createToken({
      sub: "test",
      exp: futureTimestamp(3600),
    });

    // Convert to base64
    const base64 = btoa(String.fromCharCode(...publicKey));

    const validator = await LicenseValidator.create(TEST_REALM, { publicKey: base64 });
    const result = await validator.validate(token);

    expect(result.valid).toBe(true);
  });

  test("throws for invalid key length", async () => {
    await expect(
      LicenseValidator.create(TEST_REALM, { publicKey: new Uint8Array(16) })
    ).rejects.toThrow();
  });

  test("throws for invalid key format", async () => {
    await expect(
      LicenseValidator.create(TEST_REALM, { publicKey: "not-a-valid-key" })
    ).rejects.toThrow();
  });
});

describe("internal claim validation", () => {
  describe("issuer validation", () => {
    test("rejects token with wrong issuer", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      }, { iss: "wrong-issuer" });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INVALID_ISSUER");
      }
    });

    test("rejects token with missing issuer", async () => {
      // Use raw token to skip iss default
      const token = await createRawToken(
        { alg: "EdDSA", typ: "JWT", kwv: 1 },
        { sub: "test", aud: TEST_REALM, exp: futureTimestamp(3600) }
      );

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INVALID_ISSUER");
      }
    });
  });

  describe("audience validation", () => {
    test("rejects token with wrong audience", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      }, { aud: "other-app" });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INVALID_AUDIENCE");
      }
    });

    test("accepts token with audience array containing library ID", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      }, { aud: ["other-app", TEST_REALM, "another-app"] });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(true);
    });

    test("rejects token with missing audience", async () => {
      // Use raw token to skip aud default
      const token = await createRawToken(
        { alg: "EdDSA", typ: "JWT", kwv: 1 },
        { iss: "keywrit", sub: "test", exp: futureTimestamp(3600) }
      );

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INVALID_AUDIENCE");
      }
    });
  });

  describe("version validation", () => {
    test("rejects token without kwv header", async () => {
      const token = await createRawToken(
        { alg: "EdDSA", typ: "JWT" },
        { iss: "keywrit", aud: TEST_REALM, sub: "test", exp: futureTimestamp(3600) }
      );

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INVALID_HEADER");
        expect(result.error.message).toContain("kwv");
      }
    });

    test("rejects token with unsupported version", async () => {
      const token = await createRawToken(
        { alg: "EdDSA", typ: "JWT", kwv: 999 },
        { iss: "keywrit", aud: TEST_REALM, sub: "test", exp: futureTimestamp(3600) }
      );

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const result = await validator.validate(token);

      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.error.code).toBe("INVALID_HEADER");
        expect(result.error.message).toContain("Unsupported");
      }
    });
  });
});
