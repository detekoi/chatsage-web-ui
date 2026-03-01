/**
 * Tests for api/authStatus.router.ts
 * Authentication status checking and token refresh
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import authStatusRouter from "@/api/authStatus.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock("@/tokens", () => ({
  getValidTwitchTokenForUser: jest.fn(),
  clearUserTokens: jest.fn(),
}));

import { getValidTwitchTokenForUser, clearUserTokens } from "@/tokens";
const mockGetToken = getValidTwitchTokenForUser as jest.MockedFunction<typeof getValidTwitchTokenForUser>;
const mockClearTokens = clearUserTokens as jest.MockedFunction<typeof clearUserTokens>;

const JWT_SECRET = process.env.JWT_SECRET_KEY!;

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(rateLimit({ windowMs: 60000, max: 1000 }));

  // Simulate JWT auth middleware
  app.use((req: any, _res: any, next: any) => {
    const auth = req.headers.authorization;
    if (auth?.startsWith("Bearer ")) {
      try {
        const decoded = jwt.verify(auth.slice(7), JWT_SECRET) as any;
        req.user = decoded;
      } catch { /* noop */ }
    }
    next();
  });

  app.use("/", authStatusRouter);
  return app;
}

function makeToken(payload: object) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

describe("Auth Status Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("GET /status", () => {
    it("returns authenticated status with valid Twitch token", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGetToken.mockResolvedValue("valid-access-token");

      const app = createApp();
      const res = await request(app)
        .get("/status")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.isAuthenticated).toBe(true);
      expect(res.body.needsReAuth).toBe(false);
    });

    it("returns 403 with needsReAuth when token validation fails", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGetToken.mockRejectedValue(new Error("Token is invalid"));

      const app = createApp();
      const res = await request(app)
        .get("/status")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.isAuthenticated).toBe(true);
    });
  });

  describe("POST /refresh", () => {
    it("refreshes token successfully", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockClearTokens.mockResolvedValue(true);
      mockGetToken.mockResolvedValue("refreshed-token");

      const app = createApp();
      const res = await request(app)
        .post("/refresh")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockClearTokens).toHaveBeenCalled();
    });

    it("returns 403 when refresh fails", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockClearTokens.mockResolvedValue(true);
      mockGetToken.mockRejectedValue(new Error("Refresh failed"));

      const app = createApp();
      const res = await request(app)
        .post("/refresh")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });
  });
});
