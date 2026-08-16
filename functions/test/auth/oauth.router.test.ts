/**
 * Tests for auth/oauth.router.ts
 * Twitch OAuth flow — login initiation and callback handling
 */

import express from "express";
import request from "supertest";
import axios from "axios";
import oauthRouter from "@/auth/oauth.router";
import { STATE_COOKIE_NAME } from "@/auth/state";
import { createSessionToken } from "@/auth/jwt.middleware";

jest.mock("axios");

jest.mock("@/auth/jwt.middleware", () => ({
  createSessionToken: jest.fn().mockReturnValue("test-session-token"),
}));

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

/**
 * Runs a real /twitch initiation and returns the nonce Twitch would echo back
 * along with the state cookie the browser would hold.
 * @param app - Express app under test
 * @return The `state` nonce and the matching Cookie header value
 */
async function startFlow(app: express.Express) {
  const res = await request(app).get("/twitch");

  const location = new URL(res.headers.location);
  const nonce = location.searchParams.get("state") as string;

  const setCookie = res.headers["set-cookie"] as unknown as string[];
  const stateCookie = setCookie.find((c) => c.startsWith(`${STATE_COOKIE_NAME}=`)) as string;

  return { nonce, cookie: stateCookie.split(";")[0], setCookie: stateCookie };
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

  describe("state binding", () => {
    it("sends only the opaque nonce as state, not a JSON payload", async () => {
      const app = createApp();
      const { nonce } = await startFlow(app);

      expect(nonce).toMatch(/^[0-9a-f]{64}$/);
    });

    it("sets a host-only HttpOnly SameSite=Lax state cookie", async () => {
      const app = createApp();
      const { setCookie } = await startFlow(app);

      expect(setCookie).toContain("HttpOnly");
      expect(setCookie).toContain("SameSite=Lax");
      expect(setCookie).toContain("Path=/");
      expect(setCookie).not.toContain("Domain=");
    });

    it("stores the nonce in the cookie, so state alone cannot satisfy the check", async () => {
      const app = createApp();
      const { nonce, cookie } = await startFlow(app);

      expect(cookie).toContain(encodeURIComponent(nonce));
    });

    it("rejects a callback whose state does not match the cookie", async () => {
      const app = createApp();
      const { cookie } = await startFlow(app);

      const res = await request(app)
        .get("/twitch/callback")
        .set("Cookie", cookie)
        .query({ code: "test-code", state: "a".repeat(64) });

      expect(res.status).toBe(302);
      expect(res.headers.location).toContain("error=invalid_state");
    });

    it("mints no session token and exchanges no code on a state mismatch", async () => {
      const app = createApp();
      const { cookie } = await startFlow(app);

      await request(app)
        .get("/twitch/callback")
        .set("Cookie", cookie)
        .query({ code: "test-code", state: "a".repeat(64) });

      expect(createSessionToken).not.toHaveBeenCalled();
      expect(axios.post).not.toHaveBeenCalled();
    });

    it("rejects a callback with a valid state but no cookie", async () => {
      const app = createApp();
      const { nonce } = await startFlow(app);

      const res = await request(app)
        .get("/twitch/callback")
        .query({ code: "test-code", state: nonce });

      expect(res.status).toBe(302);
      expect(res.headers.location).toContain("error=invalid_state");
      expect(createSessionToken).not.toHaveBeenCalled();
      expect(axios.post).not.toHaveBeenCalled();
    });

    it("clears the state cookie so it cannot be replayed", async () => {
      const app = createApp();
      const { nonce, cookie } = await startFlow(app);

      const res = await request(app)
        .get("/twitch/callback")
        .set("Cookie", cookie)
        .query({ code: "test-code", state: nonce });

      const cleared = (res.headers["set-cookie"] as unknown as string[])
        .find((c) => c.startsWith(`${STATE_COOKIE_NAME}=`)) as string;

      expect(cleared).toContain(`${STATE_COOKIE_NAME}=;`);
      expect(cleared).toContain("Expires=Thu, 01 Jan 1970");
    });

    it("gets past state binding and on to the code exchange on a match", async () => {
      const app = createApp();
      const { nonce, cookie } = await startFlow(app);

      const res = await request(app)
        .get("/twitch/callback")
        .set("Cookie", cookie)
        .query({ code: "test-code", state: nonce });

      // The mocked axios makes the exchange itself fail, but reaching it at all
      // proves the state check passed rather than short-circuiting.
      expect(axios.post).toHaveBeenCalled();
      expect(res.headers.location).not.toContain("error=invalid_state");
    });

    it("still reports a genuine Twitch error rather than masking it as bad state", async () => {
      const app = createApp();
      const { cookie } = await startFlow(app);

      const res = await request(app)
        .get("/twitch/callback")
        .set("Cookie", cookie)
        .query({ error: "access_denied", error_description: "User denied", state: "mismatched" });

      expect(res.headers.location).toContain("error=access_denied");
    });
  });
});
