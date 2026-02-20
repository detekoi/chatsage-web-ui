/**
 * Tests for api/commands.router.ts
 * Bot command enable/disable management
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import commandsRouter from "@/api/commands.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

const mockGet = jest.fn();
const mockSet = jest.fn().mockResolvedValue(undefined);
const mockDoc = jest.fn().mockReturnValue({
  get: mockGet,
  set: mockSet,
});
const mockCollection = jest.fn().mockReturnValue({ doc: mockDoc });

jest.mock("@/config/database", () => ({
  getDb: () => ({ collection: mockCollection }),
  FieldValue: {
    arrayRemove: jest.fn((val: string) => ({ _type: "arrayRemove", value: val })),
    arrayUnion: jest.fn((val: string) => ({ _type: "arrayUnion", value: val })),
    serverTimestamp: jest.fn(() => "SERVER_TIMESTAMP"),
  },
}));

const JWT_SECRET = process.env.JWT_SECRET_KEY!;

function createApp() {
  const app = express();
  app.use(express.json());

  // Simulate auth middleware
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

  app.use("/", commandsRouter);
  return app;
}

function makeToken(payload: object) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

describe("Commands Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("GET /", () => {
    it("returns list of commands with enabled/disabled state", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({ disabledCommands: ["ask"] }),
      });

      const app = createApp();
      const res = await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.commands).toBeDefined();
      expect(Array.isArray(res.body.commands)).toBe(true);
    });

    it("returns default state when no channel data exists", async () => {
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
    it("updates command enabled state", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ command: "ask", enabled: false });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockSet).toHaveBeenCalled();
    });

    it("returns 400 for missing command name", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ enabled: false });

      expect(res.status).toBe(400);
    });

    it("returns 400 for invalid enabled value", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ command: "ask", enabled: "not-a-boolean" });

      expect(res.status).toBe(400);
    });
  });
});
