/**
 * Tests for config/middleware.ts
 * CORS, security headers, and request timeout
 */

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

import express from "express";
import request from "supertest";
import {
  corsAndSecurityMiddleware,
  requestTimeoutMiddleware,
  requireFirestore,
  resolveTrustProxy,
  setupMiddleware,
  previewLimiter,
  apiLimiter,
  personaWriteLimiter,
} from "@/config/middleware";
import { RATE_LIMIT } from "@/config/constants";
import { logger } from "@/config/logger";

describe("corsAndSecurityMiddleware", () => {
  let mockReq: any;
  let mockRes: any;
  let mockNext: jest.Mock;

  beforeEach(() => {
    mockReq = {
      headers: {},
      method: "GET",
    };
    mockRes = {
      setHeader: jest.fn(),
      sendStatus: jest.fn(),
    };
    mockNext = jest.fn();
  });

  it("sets security headers on every request", () => {
    corsAndSecurityMiddleware(mockReq, mockRes, mockNext);

    expect(mockRes.setHeader).toHaveBeenCalledWith("X-Content-Type-Options", "nosniff");
    expect(mockRes.setHeader).toHaveBeenCalledWith("X-Frame-Options", "DENY");
    expect(mockRes.setHeader).toHaveBeenCalledWith("X-XSS-Protection", "1; mode=block");
    expect(mockRes.setHeader).toHaveBeenCalledWith("Referrer-Policy", "strict-origin-when-cross-origin");
    expect(mockNext).toHaveBeenCalled();
  });

  it("sets CORS headers for allowed origin", () => {
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    mockReq.headers.origin = frontendUrl;
    corsAndSecurityMiddleware(mockReq, mockRes, mockNext);

    expect(mockRes.setHeader).toHaveBeenCalledWith(
      "Access-Control-Allow-Origin",
      frontendUrl,
    );
    expect(mockRes.setHeader).toHaveBeenCalledWith(
      "Access-Control-Allow-Credentials",
      "true",
    );
  });

  it("does not set origin-specific CORS for disallowed origin", () => {
    mockReq.headers.origin = "https://evil-site.com";
    corsAndSecurityMiddleware(mockReq, mockRes, mockNext);

    // Should not set Allow-Origin for disallowed origin
    const originCalls = mockRes.setHeader.mock.calls.filter(
      (c: string[]) => c[0] === "Access-Control-Allow-Origin",
    );
    expect(originCalls).toHaveLength(0);
  });

  it("handles OPTIONS preflight with 204", () => {
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";
    mockReq.method = "OPTIONS";
    mockReq.headers.origin = frontendUrl;
    corsAndSecurityMiddleware(mockReq, mockRes, mockNext);

    expect(mockRes.sendStatus).toHaveBeenCalledWith(204);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("calls next for non-OPTIONS requests", () => {
    mockReq.method = "POST";
    corsAndSecurityMiddleware(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockRes.sendStatus).not.toHaveBeenCalled();
  });
});

describe("requestTimeoutMiddleware", () => {
  let mockReq: any;
  let mockRes: any;
  let mockNext: jest.Mock;

  beforeEach(() => {
    jest.useFakeTimers();
    mockReq = {};
    mockRes = {
      headersSent: false,
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      on: jest.fn(),
    };
    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it("calls next immediately", () => {
    requestTimeoutMiddleware(mockReq, mockRes, mockNext);
    expect(mockNext).toHaveBeenCalled();
  });

  it("registers finish and close handlers to clear timeout", () => {
    requestTimeoutMiddleware(mockReq, mockRes, mockNext);

    const onCalls = mockRes.on.mock.calls;
    const events = onCalls.map((c: string[]) => c[0]);
    expect(events).toContain("finish");
    expect(events).toContain("close");
  });

  it("sends 408 after timeout period", () => {
    requestTimeoutMiddleware(mockReq, mockRes, mockNext);

    jest.advanceTimersByTime(30000);

    expect(mockRes.status).toHaveBeenCalledWith(408);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        message: "Request timeout",
      }),
    );
  });

  it("does not send 408 if headers already sent", () => {
    requestTimeoutMiddleware(mockReq, mockRes, mockNext);
    mockRes.headersSent = true;

    jest.advanceTimersByTime(30000);

    expect(mockRes.status).not.toHaveBeenCalled();
  });
});

describe("requireFirestore", () => {
  let mockReq: any;
  let mockRes: any;
  let mockNext: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    mockReq = {};
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockNext = jest.fn();
  });

  it("calls next when database is available", async () => {
    // Mock the dynamic import to resolve successfully
    jest.mock("@/config/database", () => ({
      getDb: () => ({}),
    }));

    await requireFirestore(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
  });

  it("returns 500 when database is not available", async () => {
    // Mock the dynamic import to throw
    jest.mock("@/config/database", () => ({
      getDb: () => {
        throw new Error("Database not initialized");
      },
    }));

    // Need to reset module cache so our new mock takes effect
    jest.resetModules();
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { requireFirestore: freshRequireFirestore } = require("@/config/middleware");

    await freshRequireFirestore(mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        message: "Database not available",
      }),
    );
    expect(mockNext).not.toHaveBeenCalled();
  });
});

describe("rate limiters that front fetch() callers", () => {
  // The dashboard parses every API response as JSON, so a limiter must not
  // answer 429 with a text/html string.
  async function exhaust(limiter: any, max: number, locale?: string) {
    const app = express();
    app.use((req: any, _res: any, next: any) => {
      req.user = { userId: "user-1" };
      next();
    });
    app.use(limiter);
    app.post("/", (_req, res) => res.json({ success: true }));

    for (let i = 0; i < max; i++) {
      const ok = await request(app).post("/");
      expect(ok.status).toBe(200);
    }
    const blocked = request(app).post("/");
    return locale ? blocked.set("X-Locale", locale) : blocked;
  }

  it.each([
    ["previewLimiter", previewLimiter, RATE_LIMIT.PREVIEW.max],
    ["apiLimiter", apiLimiter, RATE_LIMIT.API.max],
    ["personaWriteLimiter", personaWriteLimiter, RATE_LIMIT.PROMPT_WRITE.max],
  ])("%s answers 429 with the JSON error shape once the budget is spent", async (_name, limiter, max) => {
    const limited = await exhaust(limiter, max);
    expect(limited.status).toBe(429);
    expect(limited.type).toBe("application/json");
    expect(limited.body.success).toBe(false);
    expect(typeof limited.body.message).toBe("string");
  });

  // The limiters are module singletons whose budgets the tests above already spent, so these two
  // load a fresh copy of the module to get untouched counters.
  function freshLimiters() {
    let fresh: any;
    jest.isolateModules(() => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      fresh = require("@/config/middleware");
    });
    return fresh;
  }

  it("words the 429 in the caller's language from X-Locale", async () => {
    const limited = await exhaust(freshLimiters().previewLimiter, RATE_LIMIT.PREVIEW.max, "es");
    expect(limited.status).toBe(429);
    expect(limited.body).toEqual({
      success: false,
      message: "Demasiadas vistas previas. Espera un minuto e inténtalo de nuevo.",
    });
  });

  it("keeps the English message without a locale", async () => {
    const limited = await exhaust(freshLimiters().apiLimiter, RATE_LIMIT.API.max);
    expect(limited.body.message).toBe("Too many requests. Wait one minute, then try again.");
  });

  describe("authLimiter", () => {
    // Fronts both browser navigations (plain text) and POST /auth/exchange, which auth-complete.html
    // calls with fetch() and parses as JSON.
    async function exhaustAuth(send: (app: express.Application) => any, max: number) {
      const app = express();
      app.use(express.json());
      app.use(freshLimiters().authLimiter);
      app.all("/", (_req, res) => res.json({ success: true }));
      for (let i = 0; i < max; i++) await send(app);
      return send(app);
    }

    it("answers a JSON-bodied request with the JSON error shape, localized", async () => {
      const limited = await exhaustAuth(
        (app) => request(app).post("/").set("X-Locale", "es").send({ code: "abc" }),
        RATE_LIMIT.AUTH.max,
      );
      expect(limited.status).toBe(429);
      expect(limited.type).toBe("application/json");
      expect(limited.body).toEqual({
        success: false,
        message: "Demasiados intentos de autenticación, inténtalo de nuevo más tarde.",
      });
    });

    it("still answers a browser navigation with plain text", async () => {
      const limited = await exhaustAuth((app) => request(app).get("/"), RATE_LIMIT.AUTH.max);
      expect(limited.status).toBe(429);
      expect(limited.type).toBe("text/html");
      expect(limited.text).toBe("Too many authentication attempts, please try again later.");
    });
  });
});

describe("resolveTrustProxy", () => {
  beforeEach(() => jest.clearAllMocks());

  it.each([["1", 1], ["2", 2], [" 3 ", 3]])("counts %j proxy hops from the right", (raw, hops) => {
    expect(resolveTrustProxy(raw)).toBe(hops);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it.each([[""], ["0"], ["-1"], ["1.5"], ["true"], ["abc"]])(
    "keeps trusting every hop, with a warning, for %j",
    (raw) => {
      expect(resolveTrustProxy(raw)).toBe(true);
      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining("TRUST_PROXY_HOPS"), { value: raw });
    },
  );

  it("is applied to the app by setupMiddleware", () => {
    const app = { set: jest.fn(), use: jest.fn() } as unknown as express.Application;
    setupMiddleware(app);
    expect(app.set).toHaveBeenCalledWith("trust proxy", true); // TRUST_PROXY_HOPS is unset under test
  });

  it("keys IP-based limiters on the address the nearest trusted proxy saw, not a forged one", async () => {
    const app = express();
    app.set("trust proxy", 1);
    app.get("/", (req, res) => res.json({ ip: req.ip }));

    const res = await request(app).get("/").set("X-Forwarded-For", "203.0.113.9, 198.51.100.7");

    // With one trusted hop the rightmost entry — the one our proxy appended — is the client.
    expect(res.body.ip).toBe("198.51.100.7");
  });
});
