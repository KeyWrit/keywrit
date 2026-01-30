/**
 * Tests for JWT decoding utilities
 */

import { describe, test, expect } from "bun:test";
import { decode, decodePayload } from "../src/index.ts";
import { createToken, createRawToken, TEST_LIBRARY_ID } from "./helpers.ts";

describe("decode", () => {
  test("decodes valid token", async () => {
    const token = await createToken({ sub: "user@example.com" });
    const decoded = decode(token);

    expect(decoded).not.toBeNull();
    expect(decoded?.header.alg).toBe("EdDSA");
    expect(decoded?.header.typ).toBe("JWT");
    expect(decoded?.header.kwv).toBe(1);
    expect(decoded?.payload.sub).toBe("user@example.com");
    expect(decoded?.payload.iss).toBe("keywrit");
    expect(decoded?.payload.aud).toBe(TEST_LIBRARY_ID);
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

  test("returns null for token without kwv", async () => {
    const token = await createRawToken(
      { alg: "EdDSA", typ: "JWT" }, // no kwv
      { sub: "test" }
    );
    expect(decode(token)).toBeNull();
  });

  test("returns null for token with unsupported kwv", async () => {
    const token = await createRawToken(
      { alg: "EdDSA", typ: "JWT", kwv: 999 },
      { sub: "test" }
    );
    expect(decode(token)).toBeNull();
  });
});

describe("decodePayload", () => {
  test("extracts payload only", async () => {
    const token = await createToken({ sub: "test", kind: "pro" });
    const payload = decodePayload(token);

    expect(payload?.sub).toBe("test");
    expect(payload?.kind).toBe("pro");
    expect(payload?.iss).toBe("keywrit");
  });

  test("returns null for invalid token", () => {
    expect(decodePayload("invalid")).toBeNull();
    expect(decodePayload("")).toBeNull();
  });

  test("extracts complex payload", async () => {
    const token = await createToken({
      sub: "user@example.com",
      flags: ["export", "import"],
      kind: "enterprise",
      features: { region: "us-west" },
    }, { aud: ["app1", "app2"] });
    const payload = decodePayload(token);

    expect(payload?.sub).toBe("user@example.com");
    expect(payload?.iss).toBe("keywrit");
    expect(payload?.aud).toEqual(["app1", "app2"]);
    expect(payload?.flags).toEqual(["export", "import"]);
    expect(payload?.kind).toBe("enterprise");
    expect(payload?.features).toEqual({ region: "us-west" });
  });
});
