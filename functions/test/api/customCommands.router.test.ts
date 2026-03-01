/**
 * Tests for api/customCommands.router.ts
 * Custom command CRUD operations
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import customCommandsRouter from "@/api/customCommands.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

// Build a deeply nested Firestore mock for subcollections:
// getDb().collection("customCommands").doc(channelName).collection("commands")
const mockDelete = jest.fn().mockResolvedValue(undefined);
const mockSet = jest.fn().mockResolvedValue(undefined);
const mockUpdate = jest.fn().mockResolvedValue(undefined);
const mockDocGet = jest.fn();
const mockCommandDoc = jest.fn().mockReturnValue({
  get: mockDocGet,
  set: mockSet,
  update: mockUpdate,
  delete: mockDelete,
});

const mockSnapshotGet = jest.fn();
const mockOrderBy = jest.fn().mockReturnValue({ get: mockSnapshotGet });
const mockCount = jest.fn().mockReturnValue({
  get: jest.fn().mockResolvedValue({ data: () => ({ count: 0 }) }),
});

const mockCommandsCollection = jest.fn().mockReturnValue({
  doc: mockCommandDoc,
  get: mockSnapshotGet,
  orderBy: mockOrderBy,
  count: mockCount,
});

const mockChannelDoc = jest.fn().mockReturnValue({
  collection: mockCommandsCollection,
});

const mockTopCollection = jest.fn().mockReturnValue({
  doc: mockChannelDoc,
});

jest.mock("@/config/database", () => ({
  getDb: () => ({ collection: mockTopCollection }),
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

  app.use("/", customCommandsRouter);
  return app;
}

function makeToken(payload: object) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

describe("Custom Commands Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset default mock returns
    mockSnapshotGet.mockResolvedValue({ docs: [], size: 0 });
    mockDocGet.mockResolvedValue({ exists: false });
    mockCount.mockReturnValue({
      get: jest.fn().mockResolvedValue({ data: () => ({ count: 0 }) }),
    });
  });

  describe("GET /", () => {
    it("returns list of custom commands", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockSnapshotGet.mockResolvedValue({
        docs: [
          {
            id: "hello",
            data: () => ({
              response: "Hello world!",
              permission: "everyone",
              cooldownMs: 5000,
            }),
          },
        ],
        size: 1,
      });

      const app = createApp();
      const res = await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.commands).toBeDefined();
    });
  });

  describe("POST /", () => {
    it("creates a new custom command", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockDocGet.mockResolvedValue({ exists: false });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({
          name: "greet",
          response: "Hello {user}!",
          permission: "everyone",
          cooldown: 10000,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it("returns 400 when command name is missing", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ response: "Hello!" });

      expect(res.status).toBe(400);
    });

    it("returns 400 when response is missing", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ name: "greet" });

      expect(res.status).toBe(400);
    });

    it("returns 409 when command already exists", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockDocGet.mockResolvedValue({ exists: true });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ name: "greet", response: "Hello!" });

      expect(res.status).toBe(409);
    });
  });

  describe("DELETE /:name", () => {
    it("deletes an existing command", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockDocGet.mockResolvedValue({ exists: true });

      const app = createApp();
      const res = await request(app)
        .delete("/testcmd")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockDelete).toHaveBeenCalled();
    });

    it("returns 404 for non-existent command", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockDocGet.mockResolvedValue({ exists: false });

      const app = createApp();
      const res = await request(app)
        .delete("/nonexistent")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(404);
    });
  });
});
