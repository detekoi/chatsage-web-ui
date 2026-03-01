/**
 * Tests for api/autoChat.router.ts
 * Auto-chat configuration management
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import autoChatRouter from "@/api/autoChat.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock("@/twitch/eventsub.service", () => ({
  ensureAdBreakSubscription: jest.fn().mockResolvedValue(undefined),
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

  app.use("/", autoChatRouter);
  return app;
}

function makeToken(payload: object) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

describe("AutoChat Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("GET /", () => {
    it("returns auto-chat config for existing channel", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({
          autoChatMode: "medium",
          autoChatCategories: { science: true, gaming: false },
        }),
      });

      const app = createApp();
      const res = await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.config).toBeDefined();
    });

    it("returns defaults for new channel", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({ exists: false });

      const app = createApp();
      const res = await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });
  });

  describe("POST /", () => {
    it("updates auto-chat mode", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ mode: "high" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it("returns 400 for invalid mode", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ mode: "invalid_mode" });

      expect(res.status).toBe(400);
    });
  });
});
