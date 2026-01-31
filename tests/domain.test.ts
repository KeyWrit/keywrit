/**
 * Tests for domain checking
 */

import { describe, expect, test } from "vitest";
import { LicenseValidator } from "../src/index.ts";
import {
  createToken,
  futureTimestamp,
  pastTimestamp,
  publicKeyHex,
  TEST_REALM,
} from "./helpers.ts";

describe("domain checking", () => {
  describe("checkDomain", () => {
    test("allows domain when no restrictions", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        // No allowedDomains field
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(token, "example.com");

      expect(result.allowed).toBe(true);
      expect(result.reason).toBe("no_restrictions");
    });

    test("allows exact domain match", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: ["example.com", "other.org"],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(token, "example.com");

      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    test("allows wildcard subdomain match", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: ["*.example.com"],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });

      expect(
        (await validator.checkDomain(token, "app.example.com")).allowed,
      ).toBe(true);
      expect(
        (await validator.checkDomain(token, "staging.example.com")).allowed,
      ).toBe(true);
      expect(
        (await validator.checkDomain(token, "deep.nested.example.com")).allowed,
      ).toBe(true);
    });

    test("wildcard does not match root domain", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: ["*.example.com"],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(token, "example.com");

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("domain_not_in_list");
    });

    test("rejects domain not in list", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: ["example.com"],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(token, "other.com");

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("domain_not_in_list");
    });

    test("rejects all domains when allowedDomains is empty", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: [],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(token, "example.com");

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("empty_allowlist");
    });

    test("returns expired for expired token", async () => {
      const token = await createToken({
        sub: "test",
        exp: pastTimestamp(3600),
        allowedDomains: ["example.com"],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(token, "example.com");

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("expired");
    });

    test("returns invalid_token for invalid token", async () => {
      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(
        "invalid-token",
        "example.com",
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe("invalid_token");
    });

    test("is case insensitive", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: ["Example.COM"],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const result = await validator.checkDomain(token, "example.com");

      expect(result.allowed).toBe(true);
    });
  });

  describe("getAllowedDomains", () => {
    test("returns allowed domains from token", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: ["example.com", "*.example.org"],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const domains = await validator.getAllowedDomains(token);

      expect(domains).toEqual(["example.com", "*.example.org"]);
    });

    test("returns undefined when no allowedDomains", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const domains = await validator.getAllowedDomains(token);

      expect(domains).toBeUndefined();
    });

    test("returns empty array when empty", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
        allowedDomains: [],
      });

      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const domains = await validator.getAllowedDomains(token);

      expect(domains).toEqual([]);
    });

    test("returns undefined for invalid token", async () => {
      const validator = await LicenseValidator.create(TEST_REALM, {
        publicKey: publicKeyHex,
      });
      const domains = await validator.getAllowedDomains("invalid-token");

      expect(domains).toBeUndefined();
    });
  });
});
