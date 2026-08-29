/**
 * Tests for api/language.router.ts
 * Bot response language, shared with the bot's `!botlang` command.
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import languageRouter from "@/api/language.router";

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

const mockGetChannelStreamLanguage = jest.fn();
jest.mock("@/twitch", () => ({
  getChannelStreamLanguage: (...args: unknown[]) => mockGetChannelStreamLanguage(...args),
}));

const mockGet = jest.fn();
const mockSet = jest.fn().mockResolvedValue(undefined);
const mockDelete = jest.fn().mockResolvedValue(undefined);
const mockDoc = jest.fn().mockReturnValue({
  get: mockGet,
  set: mockSet,
  delete: mockDelete,
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
        req.user = jwt.verify(auth.slice(7), JWT_SECRET) as any;
      } catch { /* noop */ }
    }
    next();
  });

  app.use("/", languageRouter);
  return app;
}

const token = () => jwt.sign(
  { login: "testuser", userId: "123", displayName: "TestUser" },
  JWT_SECRET,
  { expiresIn: "1h" },
);

describe("Language Router", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGetChannelStreamLanguage.mockResolvedValue(null);
  });

  describe("GET /", () => {
    it("reports automatic mode when no document exists", async () => {
      mockGet.mockResolvedValue({ exists: false });
      mockGetChannelStreamLanguage.mockResolvedValue("es");

      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token()}`);

      expect(res.status).toBe(200);
      expect(res.body.mode).toBe("auto");
      expect(res.body.language).toBeNull();
      expect(res.body.detected).toBe("spanish");
      expect(res.body.available).toContain("spanish");
    });

    it("reports an explicit English choice as manual, not automatic", async () => {
      mockGet.mockResolvedValue({ exists: true, data: () => ({ language: null }) });

      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token()}`);

      expect(res.body.mode).toBe("manual");
      expect(res.body.language).toBeNull();
    });

    it("reports a stored language", async () => {
      mockGet.mockResolvedValue({ exists: true, data: () => ({ language: "japanese" }) });

      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token()}`);

      expect(res.body.mode).toBe("manual");
      expect(res.body.language).toBe("japanese");
    });

    it("treats an English stream language as no signal", async () => {
      mockGet.mockResolvedValue({ exists: false });
      mockGetChannelStreamLanguage.mockResolvedValue("en");

      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token()}`);

      expect(res.body.detected).toBeNull();
    });
  });

  describe("POST /", () => {
    it("stores a chosen language", async () => {
      const res = await request(createApp())
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ language: "Spanish" });

      expect(res.status).toBe(200);
      expect(res.body.language).toBe("spanish");
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({ channelName: "testuser", language: "spanish" }),
        { merge: true },
      );
    });

    it("stores English as null so the bot reads it as an explicit choice", async () => {
      const res = await request(createApp())
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ language: "english" });

      expect(res.status).toBe(200);
      expect(res.body.mode).toBe("manual");
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({ language: null }),
        { merge: true },
      );
    });

    it("deletes the document for automatic mode", async () => {
      const res = await request(createApp())
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ mode: "auto" });

      expect(res.status).toBe(200);
      expect(res.body.mode).toBe("auto");
      expect(mockDelete).toHaveBeenCalled();
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("rejects a language outside the offered list", async () => {
      const res = await request(createApp())
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ language: "klingon" });

      expect(res.status).toBe(400);
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("rejects a non-string language", async () => {
      const res = await request(createApp())
        .post("/")
        .set("Authorization", `Bearer ${token()}`)
        .send({ language: 42 });

      expect(res.status).toBe(400);
    });
  });
});
