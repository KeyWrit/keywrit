/**
 * Tests for flag checking methods
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp, pastTimestamp, TEST_REALM } from "./helpers.ts";

describe("flag checking", () => {
  describe("hasFlag", () => {
    test("returns enabled for present flag", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export", "import"],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const result = await validator.hasFlag(token, "export");

      expect(result.enabled).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    test("returns not enabled for missing flag", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export"],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const result = await validator.hasFlag(token, "api");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("not_in_license");
    });

    test("returns not enabled for empty flags array", async () => {
      const token = await createToken({
        sub: "test",
        flags: [],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const result = await validator.hasFlag(token, "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("not_in_license");
    });

    test("returns not enabled for missing flags claim", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const result = await validator.hasFlag(token, "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("not_in_license");
    });

    test("returns expired reason for expired token", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export"],
        exp: pastTimestamp(3600),
      });

      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const result = await validator.hasFlag(token, "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("expired");
    });

    test("returns invalid_token reason for invalid token", async () => {
      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const result = await validator.hasFlag("invalid-token", "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("invalid_token");
    });
  });

  describe("hasFlags", () => {
    test("checks multiple flags at once", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export", "import"],
        exp: futureTimestamp(3600),
      });

      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const results = await validator.hasFlags(token, ["export", "import", "api"]);

      expect(results.get("export")?.enabled).toBe(true);
      expect(results.get("import")?.enabled).toBe(true);
      expect(results.get("api")?.enabled).toBe(false);
      expect(results.get("api")?.reason).toBe("not_in_license");
    });

    test("returns all not enabled for invalid token", async () => {
      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const results = await validator.hasFlags("invalid", ["export", "import"]);

      expect(results.get("export")?.enabled).toBe(false);
      expect(results.get("export")?.reason).toBe("invalid_token");
      expect(results.get("import")?.enabled).toBe(false);
      expect(results.get("import")?.reason).toBe("invalid_token");
    });

    test("returns all expired for expired token", async () => {
      const token = await createToken({
        sub: "test",
        flags: ["export", "import"],
        exp: pastTimestamp(3600),
      });

      const validator = await LicenseValidator.create({ publicKey: publicKeyHex, realm: TEST_REALM });
      const results = await validator.hasFlags(token, ["export", "import"]);

      expect(results.get("export")?.enabled).toBe(false);
      expect(results.get("export")?.reason).toBe("expired");
      expect(results.get("import")?.enabled).toBe(false);
      expect(results.get("import")?.reason).toBe("expired");
    });
  });
});
