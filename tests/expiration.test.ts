/**
 * Tests for expiration info utility
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

describe("expiration info", () => {
    test("returns correct info for valid token", async () => {
        const exp = futureTimestamp(3600);
        const token = await createToken({ sub: "test", exp });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const info = validator.getExpirationInfo(token);

        expect(info).not.toBeNull();
        expect(info?.expiresAt).toBe(exp);
        expect(info?.isExpired).toBe(false);
        expect(info?.secondsRemaining).toBeGreaterThan(3500);
        expect(info?.secondsRemaining).toBeLessThanOrEqual(3600);
        expect(info?.timeRemaining).toContain("hour");
    });

    test("returns expired info for expired token", async () => {
        const exp = pastTimestamp(3600);
        const token = await createToken({ sub: "test", exp });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const info = validator.getExpirationInfo(token);

        expect(info).not.toBeNull();
        expect(info?.isExpired).toBe(true);
        expect(info?.secondsRemaining).toBeLessThan(0);
        expect(info?.timeRemaining).toContain("hour");
    });

    test("returns null values for token without expiration", async () => {
        const token = await createToken({ sub: "test" });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const info = validator.getExpirationInfo(token);

        expect(info).not.toBeNull();
        expect(info?.expiresAt).toBeNull();
        expect(info?.isExpired).toBe(false);
        expect(info?.secondsRemaining).toBeNull();
        expect(info?.timeRemaining).toBeNull();
    });

    test("returns null for invalid token", async () => {
        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const info = validator.getExpirationInfo("invalid-token");

        expect(info).toBeNull();
    });

    test("formats time remaining in seconds", async () => {
        const exp = futureTimestamp(30);
        const token = await createToken({ sub: "test", exp });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const info = validator.getExpirationInfo(token);

        expect(info?.timeRemaining).toContain("second");
    });

    test("formats time remaining in minutes", async () => {
        const exp = futureTimestamp(300);
        const token = await createToken({ sub: "test", exp });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const info = validator.getExpirationInfo(token);

        expect(info?.timeRemaining).toContain("minute");
    });

    test("formats time remaining in days", async () => {
        const exp = futureTimestamp(86400 * 5);
        const token = await createToken({ sub: "test", exp });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const info = validator.getExpirationInfo(token);

        expect(info?.timeRemaining).toContain("day");
    });

    test("uses custom current time", async () => {
        const exp = 1700000000;
        const token = await createToken({ sub: "test", exp });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
            timing: { currentTime: exp - 3600 },
        });
        const info = validator.getExpirationInfo(token);

        expect(info?.isExpired).toBe(false);
        expect(info?.secondsRemaining).toBe(3600);
    });
});
