/**
 * Tests for tier checking methods
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp } from "./helpers.ts";

describe("tier checking", () => {
  describe("getTier", () => {
    test("returns tier from valid token", async () => {
      const token = await createToken({
        sub: "test",
        tier: "enterprise",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const tier = await validator.getTier(token);

      expect(tier).toBe("enterprise");
    });

    test("returns null when tier not set", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const tier = await validator.getTier(token);

      expect(tier).toBeNull();
    });

    test("returns null for invalid token", async () => {
      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const tier = await validator.getTier("invalid-token");

      expect(tier).toBeNull();
    });
  });

  describe("hasTier", () => {
    test("returns true for exact tier match", async () => {
      const token = await createToken({
        sub: "test",
        tier: "pro",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });

      expect(await validator.hasTier(token, "pro")).toBe(true);
    });

    test("returns true for higher tier", async () => {
      const token = await createToken({
        sub: "test",
        tier: "enterprise",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });

      expect(await validator.hasTier(token, "free")).toBe(true);
      expect(await validator.hasTier(token, "pro")).toBe(true);
      expect(await validator.hasTier(token, "enterprise")).toBe(true);
    });

    test("returns false for lower tier", async () => {
      const token = await createToken({
        sub: "test",
        tier: "free",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });

      expect(await validator.hasTier(token, "free")).toBe(true);
      expect(await validator.hasTier(token, "pro")).toBe(false);
      expect(await validator.hasTier(token, "enterprise")).toBe(false);
    });

    test("uses custom tier hierarchy from config", async () => {
      const token = await createToken({
        sub: "test",
        tier: "gold",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({
        publicKey: publicKeyHex,
        claims: {
          tierHierarchy: ["bronze", "silver", "gold", "platinum"],
        },
      });

      expect(await validator.hasTier(token, "bronze")).toBe(true);
      expect(await validator.hasTier(token, "silver")).toBe(true);
      expect(await validator.hasTier(token, "gold")).toBe(true);
      expect(await validator.hasTier(token, "platinum")).toBe(false);
    });

    test("returns false for unknown tier", async () => {
      const token = await createToken({
        sub: "test",
        tier: "unknown",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });

      expect(await validator.hasTier(token, "free")).toBe(false);
    });

    test("returns false for invalid token", async () => {
      const validator = new LicenseValidator({ publicKey: publicKeyHex });

      expect(await validator.hasTier("invalid", "free")).toBe(false);
    });

    test("returns false when no tier in token", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });

      expect(await validator.hasTier(token, "free")).toBe(false);
    });
  });
});
