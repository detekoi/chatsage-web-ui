/**
 * Tests for api/bot.router.ts
 * Bot management — status, add, remove
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import botRouter from "@/api/bot.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock("@/tokens", () => ({
  getValidTwitchTokenForUser: jest.fn().mockResolvedValue("mock-token"),
}));

jest.mock("@/twitch", () => ({
  ensureStreamEventSubscriptions: jest.fn().mockResolvedValue(undefined),
  addModerator: jest.fn().mockResolvedValue({ success: true }),
  getUserIdFromUsername: jest.fn().mockResolvedValue("bot-user-id"),
}));

jest.mock("@/utils/secrets", () => ({
  getAllowedChannelsList: jest.fn().mockResolvedValue(["testuser"]),
}));

const mockGet = jest.fn();
const mockUpdate = jest.fn().mockResolvedValue(undefined);
const mockSet = jest.fn().mockResolvedValue(undefined);
const mockDoc = jest.fn().mockReturnValue({
  get: mockGet,
  update: mockUpdate,
  set: mockSet,
});
const mockCollection = jest.fn().mockReturnValue({ doc: mockDoc });

jest.mock("@/config/database", () => ({
  getDb: () => ({ collection: mockCollection }),
  FieldValue: {
    serverTimestamp: jest.fn(() => "SERVER_TIMESTAMP"),
  },
}));

const JWT_SECRET = process.env.JWT_SECRET_KEY!;

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(rateLimit({ windowMs: 60000, max: 1000 }));

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

  app.use("/", botRouter);
  return app;
}

function makeToken(payload: object) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

describe("Bot Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("GET /status", () => {
    it("returns active status for channel with bot", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({
          isActive: true,
          channelName: "testuser",
          needsTwitchReAuth: false,
        }),
      });

      const app = createApp();
      const res = await request(app)
        .get("/status")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.isActive).toBe(true);
    });

    it("returns inactive for channel without bot", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({ exists: false });

      const app = createApp();
      const res = await request(app)
        .get("/status")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.isActive).toBe(false);
    });
  });

  describe("POST /add", () => {
    it("adds bot to channel successfully", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/add")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it("returns 403 for channels not on allow-list", async () => {
      const token = makeToken({
        login: "notallowed",
        userId: "999",
        displayName: "NotAllowed",
      });

      const app = createApp();
      const res = await request(app)
        .post("/add")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });
  });

  describe("POST /remove", () => {
    it("removes bot from channel", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({ isActive: true }),
      });

      const app = createApp();
      const res = await request(app)
        .post("/remove")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });
});
