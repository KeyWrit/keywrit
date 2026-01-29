/**
 * Tests for feature checking methods
 */

import { describe, test, expect } from "bun:test";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp, pastTimestamp } from "./helpers.ts";

describe("feature checking", () => {
  describe("hasFeature", () => {
    test("returns enabled for present feature", async () => {
      const token = await createToken({
        sub: "test",
        features: ["export", "import"],
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const result = await validator.hasFeature(token, "export");

      expect(result.enabled).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    test("returns not enabled for missing feature", async () => {
      const token = await createToken({
        sub: "test",
        features: ["export"],
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const result = await validator.hasFeature(token, "api");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("not_in_license");
    });

    test("returns not enabled for empty features array", async () => {
      const token = await createToken({
        sub: "test",
        features: [],
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const result = await validator.hasFeature(token, "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("not_in_license");
    });

    test("returns not enabled for missing features claim", async () => {
      const token = await createToken({
        sub: "test",
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const result = await validator.hasFeature(token, "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("not_in_license");
    });

    test("returns expired reason for expired token", async () => {
      const token = await createToken({
        sub: "test",
        features: ["export"],
        exp: pastTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const result = await validator.hasFeature(token, "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("expired");
    });

    test("returns invalid_token reason for invalid token", async () => {
      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const result = await validator.hasFeature("invalid-token", "export");

      expect(result.enabled).toBe(false);
      expect(result.reason).toBe("invalid_token");
    });
  });

  describe("hasFeatures", () => {
    test("checks multiple features at once", async () => {
      const token = await createToken({
        sub: "test",
        features: ["export", "import"],
        exp: futureTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const results = await validator.hasFeatures(token, ["export", "import", "api"]);

      expect(results.get("export")?.enabled).toBe(true);
      expect(results.get("import")?.enabled).toBe(true);
      expect(results.get("api")?.enabled).toBe(false);
      expect(results.get("api")?.reason).toBe("not_in_license");
    });

    test("returns all not enabled for invalid token", async () => {
      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const results = await validator.hasFeatures("invalid", ["export", "import"]);

      expect(results.get("export")?.enabled).toBe(false);
      expect(results.get("export")?.reason).toBe("invalid_token");
      expect(results.get("import")?.enabled).toBe(false);
      expect(results.get("import")?.reason).toBe("invalid_token");
    });

    test("returns all expired for expired token", async () => {
      const token = await createToken({
        sub: "test",
        features: ["export", "import"],
        exp: pastTimestamp(3600),
      });

      const validator = new LicenseValidator({ publicKey: publicKeyHex });
      const results = await validator.hasFeatures(token, ["export", "import"]);

      expect(results.get("export")?.enabled).toBe(false);
      expect(results.get("export")?.reason).toBe("expired");
      expect(results.get("import")?.enabled).toBe(false);
      expect(results.get("import")?.reason).toBe("expired");
    });
  });
});
