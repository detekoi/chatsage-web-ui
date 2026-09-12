/**
 * Tests for api/preview.router.ts
 * Proxies a dashboard "Preview" request to the bot's /internal/preview endpoint.
 */

import express from "express";
import request from "supertest";
import jwt from "jsonwebtoken";

jest.mock("@/config/logger", () => {
  const log = { error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn() };
  return { logger: { ...log, child: jest.fn(() => log) } };
});

jest.mock("@/utils/secrets", () => ({
  getInternalBotTokenValue: jest.fn().mockResolvedValue("shared-token"),
}));

jest.mock("axios", () => {
  const post = jest.fn();
  const isAxiosError = jest.fn((e: unknown) => Boolean((e as { isAxiosError?: boolean })?.isAxiosError));
  return { __esModule: true, default: { post, isAxiosError }, post, isAxiosError };
});

import axios from "axios";
import previewRouter, { BOT_TIMEOUT_MS } from "@/api/preview.router";
import { REQUEST_TIMEOUT_MS } from "@/config/constants";
import { getInternalBotTokenValue } from "@/utils/secrets";

const mockPost = axios.post as jest.MockedFunction<typeof axios.post>;
const JWT_SECRET = process.env.JWT_SECRET_KEY!;

function createApp() {
  const app = express();
  app.use(express.json());
  app.use((req: any, _res: any, next: any) => {
    const auth = req.headers.authorization;
    if (auth?.startsWith("Bearer ")) {
      try {
        req.user = jwt.verify(auth.slice(7), JWT_SECRET) as any;
      } catch { /* noop */ }
    }
    next();
  });
  app.use("/", previewRouter);
  return app;
}

const token = () =>
  jwt.sign({ login: "testuser", userId: "12345" }, JWT_SECRET, { expiresIn: "1h" });

const okPreview = { kind: "command", resolvedPrompt: "Hi testuser", response: "Hello there!", language: null };

beforeEach(() => {
  jest.clearAllMocks();
  (getInternalBotTokenValue as jest.Mock).mockResolvedValue("shared-token");
  mockPost.mockResolvedValue({ status: 200, data: { success: true, preview: okPreview } });
});

describe("POST /api/preview", () => {
  it("waits on the bot for less time than the global request timeout", () => {
    // Otherwise requestTimeoutMiddleware answers 408 first and the handler
    // later writes to a finished response.
    expect(BOT_TIMEOUT_MS).toBeLessThan(REQUEST_TIMEOUT_MS);
    expect((mockPost.mock.calls[0]?.[2] as any)?.timeout ?? BOT_TIMEOUT_MS).toBe(BOT_TIMEOUT_MS);
  });

  it("does not write a second response when the request already timed out", async () => {
    // Simulate the timeout middleware having answered 408 while the bot call was in flight.
    let capturedRes: any;
    const app = express();
    app.use(express.json());
    app.use((req: any, res: any, next: any) => {
      req.user = { login: "testuser", userId: "12345" };
      capturedRes = res;
      next();
    });
    app.use("/", previewRouter);

    mockPost.mockImplementation(async () => {
      capturedRes.status(408).json({ success: false, message: "Request timeout" });
      return { status: 200, data: { success: true, preview: okPreview } };
    });

    const res = await request(app).post("/").send({ kind: "command", prompt: "x" });
    expect(res.status).toBe(408);
  });

  it("proxies to the bot with the JWT channel and returns the preview", async () => {
    const res = await request(createApp())
      .post("/")
      .set("Authorization", `Bearer ${token()}`)
      .send({ kind: "command", prompt: "  Say hi to $(user) ", name: "Hello World", args: "foo bar" });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, preview: okPreview });

    expect(mockPost).toHaveBeenCalledTimes(1);
    const [url, body, opts] = mockPost.mock.calls[0];
    expect(url).toBe(`${process.env.BOT_PUBLIC_URL}/internal/preview`);
    expect(body).toEqual({ channel: "testuser", kind: "command", prompt: "Say hi to $(user)", name: "hello_world", args: "foo bar" });
    expect((opts as any).headers.Authorization).toBe("Bearer shared-token");
  });

  it("ignores a channel supplied in the body", async () => {
    await request(createApp())
      .post("/")
      .set("Authorization", `Bearer ${token()}`)
      .send({ kind: "timer", prompt: "x", channel: "someoneelse" });

    expect((mockPost.mock.calls[0][1] as any).channel).toBe("testuser");
  });

  it("drops args for non-command kinds and omits an empty name", async () => {
    await request(createApp())
      .post("/")
      .set("Authorization", `Bearer ${token()}`)
      .send({ kind: "checkin", prompt: "x", args: "ignored", name: "!!!" });

    expect(mockPost.mock.calls[0][1]).toEqual({ channel: "testuser", kind: "checkin", prompt: "x" });
  });

  it("rejects an unknown kind", async () => {
    const res = await request(createApp())
      .post("/")
      .set("Authorization", `Bearer ${token()}`)
      .send({ kind: "persona", prompt: "x" });

    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/kind/i);
    expect(mockPost).not.toHaveBeenCalled();
  });

  it("rejects an empty prompt and an oversized prompt", async () => {
    const empty = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "   " });
    expect(empty.status).toBe(400);

    const long = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "x".repeat(501) });
    expect(long.status).toBe(400);
    expect(long.body.message).toMatch(/500/);
    expect(mockPost).not.toHaveBeenCalled();
  });

  it("rejects oversized sample args", async () => {
    const res = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "x", args: "y".repeat(201) });
    expect(res.status).toBe(400);
    expect(mockPost).not.toHaveBeenCalled();
  });

  it("returns success:false with the preview when the bot produced no response", async () => {
    mockPost.mockResolvedValue({ status: 200, data: { success: true, preview: { ...okPreview, response: null } } });
    const res = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "x" });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(false);
    expect(res.body.preview.resolvedPrompt).toBe("Hi testuser");
    expect(res.body.message).toMatch(/did not return/i);
  });

  it("maps a bot 503 to 503 and a bot 500 to 502", async () => {
    mockPost.mockResolvedValueOnce({ status: 503, data: { success: false, message: "Preview is not configured" } });
    const unavailable = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "x" });
    expect(unavailable.status).toBe(503);

    mockPost.mockResolvedValueOnce({ status: 500, data: { success: false, message: "Failed" } });
    const failed = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "x" });
    expect(failed.status).toBe(502);
  });

  it("returns 503 when the bot is unreachable", async () => {
    mockPost.mockRejectedValue(Object.assign(new Error("ECONNREFUSED"), { isAxiosError: true, code: "ECONNREFUSED" }));
    const res = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "x" });

    expect(res.status).toBe(503);
    expect(res.body.message).toMatch(/did not respond/i);
  });

  it("returns 500 when the internal token cannot be read", async () => {
    (getInternalBotTokenValue as jest.Mock).mockRejectedValue(new Error("no secret"));
    const res = await request(createApp())
      .post("/").set("Authorization", `Bearer ${token()}`).send({ kind: "command", prompt: "x" });

    expect(res.status).toBe(500);
    expect(mockPost).not.toHaveBeenCalled();
  });
});
