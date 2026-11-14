/**
 * Tests for api/responseStyle.router.ts
 * The De-Slop switch for the bot's AI-written text
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import responseStyleRouter from "@/api/responseStyle.router";

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
  app.use("/", responseStyleRouter);
  return app;
}

const token = jwt.sign({ login: "testuser", userId: "123" }, JWT_SECRET);
const auth = { Authorization: `Bearer ${token}` };

function stored(data: Record<string, unknown> | null) {
  return { exists: data !== null, data: () => data || undefined };
}

describe("responseStyle.router", () => {
  let app: express.Express;

  beforeEach(() => {
    jest.clearAllMocks();
    app = createApp();
    mockGet.mockResolvedValue(stored(null));
    mockSet.mockResolvedValue(undefined);
  });

  describe("GET /", () => {
    it("returns off when nothing is stored, keyed by broadcaster ID", async () => {
      const res = await request(app).get("/").set(auth);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, deslop: false });
      expect(mockCollection).toHaveBeenCalledWith("channelResponseStyles");
      expect(mockDoc).toHaveBeenCalledWith("123");
      expect(mockDoc).not.toHaveBeenCalledWith("testuser");
    });

    it("returns the stored setting", async () => {
      mockGet.mockResolvedValue(stored({ deslop: true, channelName: "testuser" }));
      const res = await request(app).get("/").set(auth);
      expect(res.body).toEqual({ success: true, deslop: true });
    });

    it("treats a stored value of the wrong type as off", async () => {
      mockGet.mockResolvedValue(stored({ deslop: "true" }));
      const res = await request(app).get("/").set(auth);
      expect(res.body.deslop).toBe(false);
    });

    it("returns 500 when Firestore fails", async () => {
      mockGet.mockRejectedValue(new Error("boom"));
      const res = await request(app).get("/").set(auth);
      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);
    });
  });

  describe("POST /", () => {
    it.each([true, false])("writes deslop=%s as a merge, keyed by broadcaster ID", async (deslop) => {
      const res = await request(app).post("/").set(auth).send({ deslop });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true, deslop });
      expect(mockCollection).toHaveBeenCalledWith("channelResponseStyles");
      expect(mockDoc).toHaveBeenCalledWith("123");
      const [written, opts] = mockSet.mock.calls[0];
      expect(opts).toEqual({ merge: true });
      expect(written).toEqual({ channelName: "testuser", updatedAt: expect.any(Date), deslop });
    });

    it("writes no other field from the request", async () => {
      await request(app).post("/").set(auth).send({ deslop: true, instructions: "x", status: "approved" });
      const [written] = mockSet.mock.calls[0];
      expect(Object.keys(written).sort()).toEqual(["channelName", "deslop", "updatedAt"]);
    });

    it.each([
      [{ deslop: "true" }],
      [{ deslop: 1 }],
      [{ deslop: null }],
      [{ enabled: true }],
      [{}],
    ])("rejects %j", async (body) => {
      const res = await request(app).post("/").set(auth).send(body);
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("returns 500 when the write fails", async () => {
      mockSet.mockRejectedValue(new Error("boom"));
      const res = await request(app).post("/").set(auth).send({ deslop: true });
      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);
    });
  });
});
