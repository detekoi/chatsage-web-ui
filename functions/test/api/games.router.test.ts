/**
 * Tests for api/games.router.ts
 * Chat game config management (trivia, geo, riddle)
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import gamesRouter from "@/api/games.router";

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

  app.use("/", gamesRouter);
  return app;
}

const token = jwt.sign({ login: "testuser", userId: "123", displayName: "TestUser" }, JWT_SECRET, {
  expiresIn: "1h",
});

function post(path: string, body: object) {
  return request(createApp()).post(path).set("Authorization", `Bearer ${token}`).send(body);
}

describe("Games Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGet.mockResolvedValue({ exists: false });
  });

  describe("GET /", () => {
    it("returns the defaults for a channel with no stored configs", async () => {
      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.games.trivia).toEqual({
        difficulty: "normal",
        questionTimeSeconds: 45,
        pointsBase: 10,
        pointsTimeBonus: true,
        pointsDifficultyMultiplier: true,
        scoreTracking: true,
        topicPreferences: [],
      });
      expect(res.body.games.geo.clueIntervalSeconds).toBe(45);
      expect(res.body.games.riddle.multiRoundDelayMs).toBe(12000);
      expect(mockCollection).toHaveBeenCalledWith("triviaGameConfigs");
      expect(mockCollection).toHaveBeenCalledWith("geoGameConfigs");
      expect(mockCollection).toHaveBeenCalledWith("riddleGameConfigs");
      // Keyed by broadcaster ID, never by login
      expect(mockDoc).toHaveBeenCalledWith("123");
      expect(mockDoc).not.toHaveBeenCalledWith("testuser");
    });

    it("merges stored values and leaves out hidden or bad ones", async () => {
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({
          channelName: "testuser",
          difficulty: "hard",
          pointsBase: 5000,
          roundDurationMinutes: 4,
          recentKeywordsFetchLimit: 80,
        }),
      });

      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token}`);

      expect(res.body.games.trivia.difficulty).toBe("hard");
      expect(res.body.games.trivia.pointsBase).toBe(10);
      expect(res.body.games.trivia).not.toHaveProperty("roundDurationMinutes");
      expect(res.body.games.trivia).not.toHaveProperty("channelName");
      expect(res.body.games.geo.roundDurationMinutes).toBe(4);
      expect(res.body.games.riddle).not.toHaveProperty("recentKeywordsFetchLimit");
    });

    it("returns 500 when Firestore fails", async () => {
      mockGet.mockRejectedValue(new Error("down"));

      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);
    });
  });

  describe("POST /:game", () => {
    it("writes only the sent settings, merged into the stored doc", async () => {
      mockGet.mockResolvedValue({ exists: true, data: () => ({ difficulty: "easy", pointsBase: 20 }) });

      const res = await post("/geo", { clueIntervalSeconds: 90, pointsTimeBonus: false });

      expect(res.status).toBe(200);
      expect(mockCollection).toHaveBeenCalledWith("geoGameConfigs");
      expect(mockDoc).toHaveBeenCalledWith("123");
      const [data, opts] = mockSet.mock.calls[0];
      expect(opts).toEqual({ merge: true });
      expect(data).toEqual(expect.objectContaining({
        channelName: "testuser",
        clueIntervalSeconds: 90,
        pointsTimeBonus: false,
      }));
      expect(data).not.toHaveProperty("difficulty");
      expect(res.body.config).toEqual(expect.objectContaining({
        difficulty: "easy",
        pointsBase: 20,
        clueIntervalSeconds: 90,
        pointsTimeBonus: false,
      }));
    });

    it("cleans a list: trims, drops empty entries and repeats", async () => {
      const res = await post("/trivia", { topicPreferences: [" Space ", "", "space", "History"] });

      expect(res.status).toBe(200);
      expect(mockSet.mock.calls[0][0].topicPreferences).toEqual(["Space", "History"]);
    });

    it.each([
      ["a number out of range", "/trivia", { questionTimeSeconds: 5 }],
      ["a fraction", "/riddle", { maxRounds: 2.5 }],
      ["a number as text", "/geo", { pointsBase: "10" }],
      ["an unknown difficulty", "/trivia", { difficulty: "extreme" }],
      ["a switch that is not boolean", "/riddle", { scoreTracking: "yes" }],
      ["a list that is not a list", "/geo", { regionRestrictions: "Europe" }],
      ["a list that is too long", "/geo", { regionRestrictions: Array.from({ length: 21 }, (_, i) => `r${i}`) }],
      ["a list entry that is too long", "/trivia", { topicPreferences: ["x".repeat(61)] }],
      ["a hidden setting", "/trivia", { roundDurationMinutes: 3 }],
      ["a setting of another game", "/riddle", { clueIntervalSeconds: 60 }],
      ["an inherited name (constructor)", "/trivia", { constructor: 1 }],
      ["an inherited name (toString)", "/geo", { toString: 1 }],
      ["no settings", "/trivia", {}],
    ])("returns 400 for %s and writes nothing", async (_name, path, body) => {
      const res = await post(path, body);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(typeof res.body.message).toBe("string");
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("returns 400 for a __proto__ key and writes nothing", async () => {
      // A JS object literal would set the prototype, so send raw JSON to make "__proto__" an own key.
      const res = await request(createApp())
        .post("/riddle")
        .set("Authorization", `Bearer ${token}`)
        .set("Content-Type", "application/json")
        .send("{\"__proto__\": 1}");

      expect(res.status).toBe(400);
      expect(typeof res.body.message).toBe("string");
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("returns 400 for an unknown game", async () => {
      const res = await post("/chess", { difficulty: "hard" });

      expect(res.status).toBe(400);
      expect(mockCollection).not.toHaveBeenCalled();
    });

    it("returns 500 when the write fails", async () => {
      mockSet.mockRejectedValueOnce(new Error("down"));

      const res = await post("/trivia", { difficulty: "hard" });

      expect(res.status).toBe(500);
    });
  });

  describe("POST /:game/reset", () => {
    it("writes every default, the hidden ones included", async () => {
      const res = await post("/riddle/reset", {});

      expect(res.status).toBe(200);
      expect(mockCollection).toHaveBeenCalledWith("riddleGameConfigs");
      expect(mockDoc).toHaveBeenCalledWith("123");
      const [data, opts] = mockSet.mock.calls[0];
      expect(opts).toEqual({ merge: true });
      expect(data).toEqual(expect.objectContaining({
        maxRounds: 10,
        recentKeywordsFetchLimit: 50,
        maxRiddleGenerationRetries: 3,
      }));
      expect(res.body.config.maxRounds).toBe(10);
      expect(res.body.config).not.toHaveProperty("recentKeywordsFetchLimit");
    });

    it("returns 400 for an unknown game", async () => {
      const res = await post("/chess/reset", {});

      expect(res.status).toBe(400);
      expect(mockSet).not.toHaveBeenCalled();
    });
  });
});
