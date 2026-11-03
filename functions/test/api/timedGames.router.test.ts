/**
 * Tests for api/timedGames.router.ts
 * Settings for chat games the bot starts on a timer
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import timedGamesRouter from "@/api/timedGames.router";

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
const mockDoc = jest.fn().mockReturnValue({ get: mockGet, set: mockSet });
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
        req.user = jwt.verify(auth.slice(7), JWT_SECRET) as any;
      } catch { /* noop */ }
    }
    next();
  });
  app.use("/", timedGamesRouter);
  return app;
}

const token = jwt.sign({ login: "testuser", userId: "123" }, JWT_SECRET);
const auth = { Authorization: `Bearer ${token}` };

function stored(data: Record<string, unknown> | null) {
  return { exists: data !== null, data: () => data || undefined };
}

describe("timedGames.router", () => {
  let app: express.Express;

  beforeEach(() => {
    jest.clearAllMocks();
    app = createApp();
    mockGet.mockResolvedValue(stored(null));
  });

  describe("GET /", () => {
    it("returns the defaults (off) when nothing is stored", async () => {
      const res = await request(app).get("/").set(auth);
      expect(res.status).toBe(200);
      expect(res.body.config).toEqual({ enabled: false, intervalMinutes: 30, games: ["trivia", "geo", "riddle"] });
      expect(res.body.limits).toEqual({ minIntervalMinutes: 5, maxIntervalMinutes: 720 });
      expect(mockCollection).toHaveBeenCalledWith("timedGameConfigs");
      expect(mockDoc).toHaveBeenCalledWith("123");
      expect(mockDoc).not.toHaveBeenCalledWith("testuser");
    });

    it("returns stored settings and hides runtime fields", async () => {
      mockGet.mockResolvedValue(stored({
        enabled: true, intervalMinutes: 15, games: ["riddle"], lastGame: "riddle", lastRunAt: new Date(),
      }));
      const res = await request(app).get("/").set(auth);
      expect(res.body.config).toEqual({ enabled: true, intervalMinutes: 15, games: ["riddle"] });
    });

    it("replaces stored values of the wrong type with defaults", async () => {
      mockGet.mockResolvedValue(stored({ enabled: "yes", intervalMinutes: 2, games: ["chess"] }));
      const res = await request(app).get("/").set(auth);
      expect(res.body.config).toEqual({ enabled: false, intervalMinutes: 30, games: ["trivia", "geo", "riddle"] });
    });

    it("returns 500 when Firestore fails", async () => {
      mockGet.mockRejectedValue(new Error("boom"));
      const res = await request(app).get("/").set(auth);
      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);
    });
  });

  describe("POST /", () => {
    it("writes only the sent settings, keyed by broadcaster ID", async () => {
      mockGet.mockResolvedValue(stored({ enabled: true, intervalMinutes: 30, games: ["trivia", "geo", "riddle"] }));
      const res = await request(app).post("/").set(auth).send({ enabled: true });
      expect(res.status).toBe(200);
      expect(mockDoc).toHaveBeenCalledWith("123");
      const [written, opts] = mockSet.mock.calls[0];
      expect(opts).toEqual({ merge: true });
      expect(written).toEqual({ channelName: "testuser", updatedAt: expect.any(Date), enabled: true });
    });

    it("stores the game list in canonical order", async () => {
      await request(app).post("/").set(auth).send({ games: ["riddle", "trivia"], intervalMinutes: 60 });
      const [written] = mockSet.mock.calls[0];
      expect(written.games).toEqual(["trivia", "riddle"]);
      expect(written.intervalMinutes).toBe(60);
    });

    it("never writes the bot's runtime fields", async () => {
      await request(app).post("/").set(auth).send({ enabled: false, lastRunAt: null, lastGame: "geo" });
      const [written] = mockSet.mock.calls[0];
      expect(written).not.toHaveProperty("lastRunAt");
      expect(written).not.toHaveProperty("lastGame");
    });

    it.each([
      [{ enabled: "true" }],
      [{ intervalMinutes: 4 }],
      [{ intervalMinutes: 721 }],
      [{ intervalMinutes: 10.5 }],
      [{ intervalMinutes: "30" }],
      [{ games: [] }],
      [{ games: ["trivia", "chess"] }],
      [{ games: "trivia" }],
      [{}],
    ])("rejects %j", async (body) => {
      const res = await request(app).post("/").set(auth).send(body);
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("returns 500 when the write fails", async () => {
      mockSet.mockRejectedValueOnce(new Error("boom"));
      const res = await request(app).post("/").set(auth).send({ enabled: true });
      expect(res.status).toBe(500);
    });
  });
});
