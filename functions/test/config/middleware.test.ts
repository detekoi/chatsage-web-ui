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

import {
  corsAndSecurityMiddleware,
  requestTimeoutMiddleware,
  requireFirestore,
} from "@/config/middleware";

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
