/**
 * Tests for JWT decoding utilities
 */

import { describe, test, expect } from "bun:test";
import { decode, decodePayload } from "../src/index.ts";
import { createToken } from "./helpers.ts";

describe("decode", () => {
  test("decodes valid token", async () => {
    const token = await createToken({ sub: "user@example.com" });
    const decoded = decode(token);

    expect(decoded).not.toBeNull();
    expect(decoded?.header.alg).toBe("EdDSA");
    expect(decoded?.header.typ).toBe("JWT");
    expect(decoded?.payload.sub).toBe("user@example.com");
  });

  test("returns null for malformed token", () => {
    expect(decode("not-a-token")).toBeNull();
    expect(decode("only.two")).toBeNull();
    expect(decode("")).toBeNull();
  });

  test("returns null for token with wrong number of parts", () => {
    expect(decode("a.b.c.d")).toBeNull();
    expect(decode("single")).toBeNull();
  });

  test("returns null for invalid base64", () => {
    expect(decode("!!!.@@@.###")).toBeNull();
  });
});

describe("decodePayload", () => {
  test("extracts payload only", async () => {
    const token = await createToken({ sub: "test", tier: "pro" });
    const payload = decodePayload(token);

    expect(payload?.sub).toBe("test");
    expect(payload?.tier).toBe("pro");
  });

  test("returns null for invalid token", () => {
    expect(decodePayload("invalid")).toBeNull();
    expect(decodePayload("")).toBeNull();
  });

  test("extracts complex payload", async () => {
    const token = await createToken({
      sub: "user@example.com",
      iss: "mycompany",
      aud: ["app1", "app2"],
      features: ["export", "import"],
      tier: "enterprise",
      seats: 100,
      meta: { region: "us-west" },
    });
    const payload = decodePayload(token);

    expect(payload?.sub).toBe("user@example.com");
    expect(payload?.iss).toBe("mycompany");
    expect(payload?.aud).toEqual(["app1", "app2"]);
    expect(payload?.features).toEqual(["export", "import"]);
    expect(payload?.tier).toBe("enterprise");
    expect(payload?.seats).toBe(100);
    expect(payload?.meta).toEqual({ region: "us-west" });
  });
});
