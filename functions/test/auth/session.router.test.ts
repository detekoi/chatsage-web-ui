/**
 * Tests for auth/session.router.ts
 * Session management — logout
 */

import express from "express";
import request from "supertest";
import sessionRouter from "@/auth/session.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

function createApp() {
  const app = express();
  app.use(express.json());
  app.use("/", sessionRouter);
  return app;
}

describe("Session Router", () => {
  describe("GET /logout", () => {
    it("clears session_token cookie and redirects", async () => {
      const app = createApp();
      const res = await request(app).get("/logout");

      expect(res.status).toBe(302);
      expect(res.headers["set-cookie"]).toBeDefined();
      const cookieHeader = res.headers["set-cookie"];
      const cookieStr = Array.isArray(cookieHeader) ? cookieHeader.join("; ") : cookieHeader;
      expect(cookieStr).toMatch(/session_token=;/);
    });
  });

  describe("POST /api/logout", () => {
    it("clears session_token cookie and returns JSON response", async () => {
      const app = createApp();
      const res = await request(app).post("/api/logout");

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.headers["set-cookie"]).toBeDefined();
    });

    it("confirms the logout in the language on screen", async () => {
      const res = await request(createApp()).post("/api/logout").set("X-Locale", "ja");

      expect(res.body.message).toBe("ログアウトしました");
    });

    it("confirms the logout in English without a locale", async () => {
      const res = await request(createApp()).post("/api/logout");

      expect(res.body.message).toBe("Logged out successfully");
    });
  });
});
