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
  trustCloudRunProxies,
  setupMiddleware,
  previewLimiter,
  apiLimiter,
  personaWriteLimiter,
} from "@/config/middleware";
import { RATE_LIMIT } from "@/config/constants";

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

describe("trustCloudRunProxies", () => {
  // Under supertest the socket peer is loopback, standing in for Cloud Run's front end.
  const ipApp = () => {
    const app = express();
    app.set("trust proxy", trustCloudRunProxies);
    app.get("/", (req, res) => res.json({ ip: req.ip }));
    return app;
  };
  const ipFor = async (xff?: string) => {
    const req = request(ipApp()).get("/");
    return (await (xff === undefined ? req : req.set("X-Forwarded-For", xff))).body.ip;
  };

  it("takes the client from a Firebase Hosting chain", async () => {
    expect(await ipFor("198.51.100.7, 66.249.84.137")).toBe("198.51.100.7");
    expect(await ipFor("198.51.100.7, 74.125.209.166")).toBe("198.51.100.7");
  });

  it("takes the address Cloud Run saw on the function URL", async () => {
    expect(await ipFor("198.51.100.7")).toBe("198.51.100.7");
  });

  it("ignores entries a client forges on the function URL, even ones that look like Hosting", async () => {
    expect(await ipFor("203.0.113.9, 198.51.100.7")).toBe("198.51.100.7");
    expect(await ipFor("203.0.113.9, 66.249.84.1, 198.51.100.7")).toBe("198.51.100.7");
  });

  it("never looks past the Hosting hop", async () => {
    expect(await ipFor("203.0.113.9, 66.249.84.1, 74.125.209.166")).toBe("66.249.84.1");
  });

  it("falls back to the socket peer without X-Forwarded-For", async () => {
    // A plain IPv4 address, not ::ffff:127.0.0.1, because test/setup.ts binds supertest to 127.0.0.1.
    expect(await ipFor()).toBe("127.0.0.1");
  });

  it.each([
    ["Hosting egress", "66.249.84.137", 1, true],
    ["IPv4-mapped Hosting egress", "::ffff:66.249.84.137", 1, true],
    ["Google Cloud customer address", "35.192.0.1", 1, false],
    ["ordinary client", "198.51.100.7", 1, false],
    ["IPv6 address", "2001:4860::1", 1, false],
    ["malformed entry", "not-an-ip", 1, false],
    ["Hosting egress beyond the first hop", "66.249.84.137", 2, false],
  ])("trusts a %s: %s at hop %d -> %s", (_label, addr, hop, trusted) => {
    expect(trustCloudRunProxies(addr, hop)).toBe(trusted);
  });

  it("is applied to the app by setupMiddleware", () => {
    const app = { set: jest.fn(), use: jest.fn() } as unknown as express.Application;
    setupMiddleware(app);
    expect(app.set).toHaveBeenCalledWith("trust proxy", trustCloudRunProxies);
  });
});
