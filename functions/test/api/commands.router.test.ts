/**
 * Tests for api/commands.router.ts
 * Bot command enable/disable management
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
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
    arrayRemove: jest.fn((...vals: string[]) => ({ _type: "arrayRemove", value: vals.length === 1 ? vals[0] : vals })),
    arrayUnion: jest.fn((val: string) => ({ _type: "arrayUnion", value: val })),
    serverTimestamp: jest.fn(() => "SERVER_TIMESTAMP"),
  },
}));

const JWT_SECRET = process.env.JWT_SECRET_KEY!;

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(rateLimit({ windowMs: 60000, max: 1000 }));

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

    it("reports always-on commands as enabled even when stored as disabled", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({ disabledCommands: ["enable", "forgetme", "trivia"] }),
      });

      const app = createApp();
      const res = await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token}`);

      const byName = Object.fromEntries(res.body.commands.map((c: any) => [c.name, c]));
      expect(byName.enable).toEqual(expect.objectContaining({ enabled: true, alwaysOn: true }));
      expect(byName.disable).toEqual(expect.objectContaining({ enabled: true, alwaysOn: true }));
      expect(byName.forgetme).toEqual(expect.objectContaining({ enabled: true, alwaysOn: true }));
      expect(byName.trivia).toEqual(expect.objectContaining({ enabled: false, alwaysOn: false }));
      expect(byName.timer).toEqual(expect.objectContaining({ enabled: true, alwaysOn: false }));
      // The stale always-on entries are cleared so a bot that still obeys them stops doing so.
      expect(mockSet).toHaveBeenCalledWith(
        { disabledCommands: { _type: "arrayRemove", value: ["enable", "forgetme"] } },
        { merge: true },
      );
    });

    it("still answers when clearing stale always-on entries fails", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({ disabledCommands: ["disable"] }),
      });
      mockSet.mockRejectedValueOnce(new Error("write failed"));

      const app = createApp();
      const res = await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it("does not write when no always-on command is stored as disabled", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({ disabledCommands: ["trivia"] }),
      });

      const app = createApp();
      await request(app)
        .get("/")
        .set("Authorization", `Bearer ${token}`);

      expect(mockSet).not.toHaveBeenCalled();
    });

    it("reports the !so options with their defaults, and only !so has options", async () => {
      const token = makeToken({ login: "testuser", userId: "123", displayName: "TestUser" });
      mockGet.mockResolvedValue({
        exists: true,
        data: () => ({ commandOptions: { so: { aiMessage: false, twitchShoutout: "yes" } } }),
      });

      const res = await request(createApp()).get("/").set("Authorization", `Bearer ${token}`);

      const byName = Object.fromEntries(res.body.commands.map((c: any) => [c.name, c]));
      // A stored value that is not a boolean falls back to the default
      expect(byName.so.options).toEqual({ aiMessage: false, twitchShoutout: true });
      expect(byName.ping.options).toBeUndefined();
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
      // Keyed by broadcaster ID, never by login
      expect(mockDoc).toHaveBeenCalledWith("123");
      expect(mockDoc).not.toHaveBeenCalledWith("testuser");
    });

    it.each(["enable", "disable", "forgetme", "Enable", " enable "])("refuses to turn off the always-on command %p", async (command) => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ command, enabled: false });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("still lets an always-on command be turned on, which clears a stored disable", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ command: "enable", enabled: true });

      expect(res.status).toBe(200);
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({ disabledCommands: { _type: "arrayRemove", value: "enable" } }),
        { merge: true },
      );
    });

    it("stores the name trimmed and lowercased", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ command: " ASK ", enabled: false });

      expect(res.status).toBe(200);
      expect(mockSet).toHaveBeenCalledWith(
        expect.objectContaining({ disabledCommands: { _type: "arrayUnion", value: "ask" } }),
        { merge: true },
      );
    });

    it("returns 400 for a command the bot does not have", async () => {
      const token = makeToken({
        login: "testuser",
        userId: "123",
        displayName: "TestUser",
      });

      const app = createApp();
      const res = await request(app)
        .post("/")
        .set("Authorization", `Bearer ${token}`)
        .send({ command: "enable\u200b", enabled: false });

      expect(res.status).toBe(400);
      expect(mockSet).not.toHaveBeenCalled();
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
  describe("POST /options", () => {
    const token = () => makeToken({ login: "testuser", userId: "123", displayName: "TestUser" });

    it("stores one !so option on the channel document", async () => {
      const res = await request(createApp())
        .post("/options")
        .set("Authorization", `Bearer ${token()}`)
        .send({ command: " SO ", option: "aiMessage", value: false });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(mockDoc).toHaveBeenCalledWith("123");
      expect(mockSet).toHaveBeenCalledWith(
        { commandOptions: { so: { aiMessage: false } }, channelName: "testuser" },
        { merge: true },
      );
    });

    it.each([
      ["a command without options", { command: "ping", option: "aiMessage", value: true }],
      ["an unknown option", { command: "so", option: "volume", value: true }],
      ["an inherited property name", { command: "so", option: "toString", value: true }],
      ["a command that names an Object property", { command: "constructor", option: "name", value: true }],
      ["a command that names the prototype", { command: "__proto__", option: "hasOwnProperty", value: true }],
      ["a value that is not a boolean", { command: "so", option: "twitchShoutout", value: "off" }],
    ])("returns 400 for %s", async (_label, body) => {
      const res = await request(createApp())
        .post("/options")
        .set("Authorization", `Bearer ${token()}`)
        .send(body);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(mockSet).not.toHaveBeenCalled();
    });

    it("names the value, not the enabled field, when the value is not a boolean", async () => {
      const res = await request(createApp())
        .post("/options")
        .set("Authorization", `Bearer ${token()}`)
        .send({ command: "so", option: "aiMessage", value: "off" });

      expect(res.status).toBe(400);
      expect(res.body.message).toBe("The option value must be true or false.");
    });

    it("returns 500 when the write fails", async () => {
      mockSet.mockRejectedValueOnce(new Error("write failed"));

      const res = await request(createApp())
        .post("/options")
        .set("Authorization", `Bearer ${token()}`)
        .send({ command: "so", option: "twitchShoutout", value: true });

      expect(res.status).toBe(500);
      expect(res.body.success).toBe(false);
    });
  });
});
