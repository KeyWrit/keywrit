/**
 * Tests for signature verification
 */

import { describe, test, expect } from "bun:test";
import * as ed25519 from "@noble/ed25519";
import { LicenseValidator } from "../src/index.ts";
import { createToken, publicKeyHex, futureTimestamp } from "./helpers.ts";

describe("signature verification", () => {
  test("validates correct signature", async () => {
    const token = await createToken({
      sub: "user@example.com",
      exp: futureTimestamp(3600),
    });

    const validator = new LicenseValidator({ publicKey: publicKeyHex });
    const result = await validator.validate(token);

    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.license.sub).toBe("user@example.com");
    }
  });

  test("rejects invalid signature", async () => {
    // Create token with different key
    const otherPrivate = ed25519.utils.randomSecretKey();
    const token = await createToken(
      { sub: "test", exp: futureTimestamp(3600) },
      { privateKey: otherPrivate }
    );

    const validator = new LicenseValidator({ publicKey: publicKeyHex });
    const result = await validator.validate(token);

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error.code).toBe("SIGNATURE_VERIFICATION_FAILED");
    }
  });

  test("rejects tampered payload", async () => {
    const token = await createToken({
      sub: "user@example.com",
      exp: futureTimestamp(3600),
    });

    // Tamper with the token by changing the payload
    const parts = token.split(".");
    const tamperedPayload = btoa(JSON.stringify({ sub: "hacker@evil.com" }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const validator = new LicenseValidator({ publicKey: publicKeyHex });
    const result = await validator.validate(tamperedToken);

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.error.code).toBe("SIGNATURE_VERIFICATION_FAILED");
    }
  });

  test("provides unverified payload on signature failure", async () => {
    const otherPrivate = ed25519.utils.randomSecretKey();
    const token = await createToken(
      { sub: "test", tier: "pro", exp: futureTimestamp(3600) },
      { privateKey: otherPrivate }
    );

    const validator = new LicenseValidator({ publicKey: publicKeyHex });
    const result = await validator.validate(token);

    expect(result.valid).toBe(false);
    if (!result.valid) {
      expect(result.unverifiedPayload?.sub).toBe("test");
      expect(result.unverifiedPayload?.tier).toBe("pro");
    }
  });
});
