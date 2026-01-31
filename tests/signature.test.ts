/**
 * Tests for signature verification
 */

import * as ed25519 from "@noble/ed25519";
import { describe, expect, test } from "vitest";
import { LicenseValidator } from "../src/index.ts";
import { verifySignature } from "../src/jwt/verify.ts";
import { decode as base64urlDecode } from "../src/utils/base64url.ts";
import { normalizePublicKey } from "../src/utils/keys.ts";
import {
    createToken,
    futureTimestamp,
    publicKeyHex,
    TEST_REALM,
} from "./helpers.ts";

describe("signature verification", () => {
    test("validates correct signature", async () => {
        const token = await createToken({
            sub: "user@example.com",
            exp: futureTimestamp(3600),
        });

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
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
            { privateKey: otherPrivate },
        );

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
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

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const result = await validator.validate(tamperedToken);

        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(result.error.code).toBe("SIGNATURE_VERIFICATION_FAILED");
        }
    });

    test("provides unverified payload on signature failure", async () => {
        const otherPrivate = ed25519.utils.randomSecretKey();
        const token = await createToken(
            { sub: "test", kind: "pro", exp: futureTimestamp(3600) },
            { privateKey: otherPrivate },
        );

        const validator = await LicenseValidator.create(TEST_REALM, {
            publicKey: publicKeyHex,
        });
        const result = await validator.validate(token);

        expect(result.valid).toBe(false);
        if (!result.valid) {
            expect(result.unverifiedPayload?.sub).toBe("test");
            expect(result.unverifiedPayload?.kind).toBe("pro");
        }
    });

    test("validates known token with known public key", async () => {
        const token =
            "eyJhbGciOiJFZERTQSJ9.eyJqdGkiOiI0N2RhMzQ3My04NDcwLTQ0OGEtODc5Mi1lMDY4MDhlODg2YTYiLCJzdWIiOiJ0ZXN0IiwibmJmIjoxNzY5ODkzNzE3LCJpYXQiOjE3Njk4OTQwMTd9.3oDDCNrT7p3jjx7YEEV319IZWtpmPWK4NufT5EsmIFZ-itIWvZ9LcROYJbX4NTA-sRJch5_AaVmXdnxBgpc3BA";
        const knownPublicKey =
            "04eef00b46b284a4190fd3b294b00b15b9737650e92d8fafb9f84e80f15a83f4";

        const parts = token.split(".");
        const [headerB64, payloadB64, signatureB64] = parts as [
            string,
            string,
            string,
        ];

        const signature = base64urlDecode(signatureB64);
        const publicKey = normalizePublicKey(knownPublicKey);

        const decoded = {
            header: { alg: "EdDSA" as const },
            payload: {},
            signature,
            signingInput: `${headerB64}.${payloadB64}`,
        };

        const result = await verifySignature(decoded, publicKey);

        expect(result.success).toBe(true);
    });
});
