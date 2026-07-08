/**
 * Tests for api/timers.router.ts
 * Timed message CRUD operations
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import timersRouter from "@/api/timers.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

// Build a deeply nested Firestore mock for subcollections:
// getDb().collection("channelTimers").doc(channelName).collection("timers")
const mockDelete = jest.fn().mockResolvedValue(undefined);
const mockSet = jest.fn().mockResolvedValue(undefined);
const mockUpdate = jest.fn().mockResolvedValue(undefined);
const mockDocGet = jest.fn();
const mockTimerDoc = jest.fn().mockReturnValue({
  get: mockDocGet,
  set: mockSet,
  update: mockUpdate,
  delete: mockDelete,
});

const mockSnapshotGet = jest.fn().mockResolvedValue({
  empty: true,
  size: 0,
  docs: [],
});
const mockOrderBy = jest.fn().mockReturnValue({ get: mockSnapshotGet });
const mockCount = jest.fn().mockReturnValue({
  get: jest.fn().mockResolvedValue({ data: () => ({ count: 0 }) }),
});

const mockTimersCollection = jest.fn().mockReturnValue({
  doc: mockTimerDoc,
  get: mockSnapshotGet,
  orderBy: mockOrderBy,
  count: mockCount,
});

const mockParentSet = jest.fn().mockResolvedValue(undefined);
const mockChannelDoc = jest.fn().mockReturnValue({
  collection: mockTimersCollection,
  set: mockParentSet,
});

const mockTopCollection = jest.fn().mockReturnValue({
  doc: mockChannelDoc,
});

const mockTransaction = {
  get: jest.fn(async (ref) => ref.get()),
  create: mockSet,
  set: mockParentSet,
};

jest.mock("@/config/database", () => ({
  getDb: () => ({
    collection: mockTopCollection,
    runTransaction: jest.fn(async (cb) => cb(mockTransaction)),
  }),
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

  app.use("/", timersRouter);
  return app;
}

function makeToken(payload: object) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

const token = () => makeToken({ login: "testuser", userId: "123", displayName: "TestUser" });

describe("Timers Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSnapshotGet.mockResolvedValue({ docs: [], size: 0 });
    mockDocGet.mockResolvedValue({ exists: false });
    mockCount.mockReturnValue({
      get: jest.fn().mockResolvedValue({ data: () => ({ count: 0 }) }),
    });
  });

  describe("GET /", () => {
    it("returns list of timers", async () => {
      mockSnapshotGet.mockResolvedValue({
        docs: [
          {
            id: "promo",
            data: () => ({
              response: "Follow the socials!",
              type: "text",
              intervalMinutes: 30,
              minChatLines: 5,
              enabled: true,
            }),
          },
        ],
        size: 1,
      });

      const app = createApp();
      const res = await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token()}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.timers).toHaveLength(1);
      expect(res.body.timers[0].name).toBe("promo");
    });
  });

  describe("POST /", () => {
    it("creates a new timer with defaults", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo", response: "Follow the socials!" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockSet).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          response: "Follow the socials!",
          type: "text",
          intervalMinutes: 15,
          minChatLines: 5,
          enabled: true,
          useCount: 0,
          lastRunAt: null,
          createdBy: "testuser",
        }),
      );
      // Parent channel doc is created so the bot's loaders can list it
      expect(mockParentSet).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ channelName: "testuser" }),
        { merge: true },
      );
    });

    it("creates an AI (prompt) timer with custom interval and lines", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({
          name: "hype",
          response: "Hype up chat about the current game",
          type: "prompt",
          intervalMinutes: 20,
          minChatLines: 10,
        });

      expect(res.status).toBe(200);
      expect(mockSet).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ type: "prompt", intervalMinutes: 20, minChatLines: 10 }),
      );
    });

    it("returns 400 for a reserved timer name", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "list", response: "Hello!" });

      expect(res.status).toBe(400);
    });

    it("returns 400 when name is missing", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ response: "Hello!" });

      expect(res.status).toBe(400);
    });

    it("returns 400 when response is missing", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo" });

      expect(res.status).toBe(400);
    });

    it("returns 400 for an out-of-range interval", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo", response: "Hello!", intervalMinutes: 1 });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain("Interval");
    });

    it("returns 400 for out-of-range minChatLines", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo", response: "Hello!", minChatLines: 500 });

      expect(res.status).toBe(400);
    });

    it("returns 400 for user-dependent variables in text timers", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo", response: "Thanks $(user)!" });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain("$(user)");
    });

    it("allows channel-scoped variables in text timers", async () => {
      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo", response: "Playing $(game) for $(uptime)!" });

      expect(res.status).toBe(200);
    });

    it("returns 409 when timer already exists", async () => {
      mockDocGet.mockResolvedValue({ exists: true });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo", response: "Hello!" });

      expect(res.status).toBe(409);
    });

    it("returns 400 when the timer limit is reached", async () => {
      mockSnapshotGet.mockResolvedValue({ size: 20 });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ name: "promo", response: "Hello!" });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain("Maximum");
    });
  });

  describe("PUT /:name", () => {
    it("updates timer fields", async () => {
      mockDocGet.mockResolvedValue({ exists: true, data: () => ({ type: "text" }) });

      const app = createApp();
      const res = await request(app)
        .put("/promo")
        .set("Authorization", `Bearer ${token()}`)
        .send({ intervalMinutes: 45, enabled: false });

      expect(res.status).toBe(200);
      expect(mockUpdate).toHaveBeenCalledWith(
        expect.objectContaining({ intervalMinutes: 45, enabled: false }),
      );
    });

    it("ignores client attempts to write lastRunAt and useCount", async () => {
      mockDocGet.mockResolvedValue({ exists: true, data: () => ({ type: "text" }) });

      const app = createApp();
      const res = await request(app)
        .put("/promo")
        .set("Authorization", `Bearer ${token()}`)
        .send({ enabled: true, lastRunAt: "now", useCount: 999 });

      expect(res.status).toBe(200);
      const updateArg = mockUpdate.mock.calls[0][0];
      expect(updateArg.lastRunAt).toBeUndefined();
      expect(updateArg.useCount).toBeUndefined();
    });

    it("validates response against the timer's effective type", async () => {
      mockDocGet.mockResolvedValue({ exists: true, data: () => ({ type: "text" }) });

      const app = createApp();
      const res = await request(app)
        .put("/promo")
        .set("Authorization", `Bearer ${token()}`)
        .send({ response: "Hi $(user)!" });

      expect(res.status).toBe(400);
    });

    it("returns 404 for non-existent timer", async () => {
      mockDocGet.mockResolvedValue({ exists: false });

      const app = createApp();
      const res = await request(app)
        .put("/promo")
        .set("Authorization", `Bearer ${token()}`)
        .send({ enabled: false });

      expect(res.status).toBe(404);
    });
  });

  describe("DELETE /:name", () => {
    it("deletes an existing timer", async () => {
      mockDocGet.mockResolvedValue({ exists: true });

      const app = createApp();
      const res = await request(app)
        .delete("/promo")
        .set("Authorization", `Bearer ${token()}`);

      expect(res.status).toBe(200);
      expect(mockDelete).toHaveBeenCalled();
    });

    it("returns 404 for non-existent timer", async () => {
      mockDocGet.mockResolvedValue({ exists: false });

      const app = createApp();
      const res = await request(app)
        .delete("/nonexistent")
        .set("Authorization", `Bearer ${token()}`);

      expect(res.status).toBe(404);
    });
  });
});
