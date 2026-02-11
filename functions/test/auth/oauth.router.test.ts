/**
 * Tests for auth/oauth.router.ts
 * Twitch OAuth flow — login initiation and callback handling
 */

import express from "express";
import request from "supertest";
import oauthRouter from "@/auth/oauth.router";

jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

jest.mock("@/config/database", () => ({
    getDb: () => ({
        collection: jest.fn().mockReturnValue({
            doc: jest.fn().mockReturnValue({
                set: jest.fn().mockResolvedValue(undefined),
            }),
        }),
    }),
}));

jest.mock("@/tokens/firestoreRefreshToken.service", () => ({
    storeTwitchRefreshToken: jest.fn().mockResolvedValue(undefined),
}));

function createApp() {
    const app = express();
    app.use(express.json());
    app.use("/", oauthRouter);
    return app;
}

describe("OAuth Router", () => {
    describe("GET /twitch", () => {
        it("redirects to Twitch authorization URL", async () => {
            const app = createApp();
            const res = await request(app).get("/twitch");

            expect(res.status).toBe(302);
            expect(res.headers.location).toContain("id.twitch.tv/oauth2/authorize");
            expect(res.headers.location).toContain("response_type=code");
        });

        it("includes client_id in redirect URL", async () => {
            const app = createApp();
            const res = await request(app).get("/twitch");

            expect(res.headers.location).toContain("client_id=");
        });

        it("includes state parameter for CSRF protection", async () => {
            const app = createApp();
            const res = await request(app).get("/twitch");

            expect(res.headers.location).toContain("state=");
        });

        it("includes required scopes", async () => {
            const app = createApp();
            const res = await request(app).get("/twitch");

            // Should include at least one scope
            expect(res.headers.location).toContain("scope=");
        });
    });

    describe("GET /twitch/callback", () => {
        it("redirects to error page when no code is provided", async () => {
            const app = createApp();
            const res = await request(app).get("/twitch/callback");

            expect(res.status).toBe(302);
            expect(res.headers.location).toContain("auth-error");
        });

        it("redirects to error page with invalid state", async () => {
            const app = createApp();
            const res = await request(app)
                .get("/twitch/callback")
                .query({ code: "test-code", state: "bad-state" });

            expect(res.status).toBe(302);
            expect(res.headers.location).toContain("auth-error");
        });
    });
});
