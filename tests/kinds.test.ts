/**
 * Tests for kind checking methods
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp, TEST_REALM } from "./helpers.ts";

describe("kind checking", () => {
  describe("getKind", () => {
    test("returns kind from valid token", async () => {
      const token = await createToken({
        sub: "test",
        kind: "enterprise",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const kind = await validator.getKind(token);

      expect(kind).toBe("enterprise");
    });

    test("returns null when kind not set", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const kind = await validator.getKind(token);

      expect(kind).toBeNull();
    });

    test("returns null for invalid token", async () => {
      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });
      const kind = await validator.getKind("invalid-token");

      expect(kind).toBeNull();
    });
  });

  describe("hasKind", () => {
    test("returns true for exact kind match", async () => {
      const token = await createToken({
        sub: "test",
        kind: "pro",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });

      expect(await validator.hasKind(token, "pro")).toBe(true);
    });

    test("returns false for different kind", async () => {
      const token = await createToken({
        sub: "test",
        kind: "free",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });

      expect(await validator.hasKind(token, "free")).toBe(true);
      expect(await validator.hasKind(token, "pro")).toBe(false);
      expect(await validator.hasKind(token, "enterprise")).toBe(false);
    });

    test("returns false for invalid token", async () => {
      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });

      expect(await validator.hasKind("invalid", "free")).toBe(false);
    });

    test("returns false when no kind in token", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, { publicKey: publicKeyHex });

      expect(await validator.hasKind(token, "free")).toBe(false);
    });
  });
});
