/**
 * Tests for utils/errors.ts
 * Error handling utilities, custom error classes, and error response helpers
 */

import {
  sanitizeErrorMessage,
  needsReAuth,
  handleApiError,
  redirectToFrontendWithError,
  AuthError,
  ValidationError,
  TwitchApiError,
} from "@/utils/errors";

// Mock dependencies
jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

// ─── sanitizeErrorMessage ──────────────────────────────────────────────────────

describe("sanitizeErrorMessage", () => {
  const defaultMsg = "Something went wrong";

  it("returns default message in production", () => {
    const origEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      const result = sanitizeErrorMessage(new Error("secret internal detail"), defaultMsg);
      expect(result).toBe(defaultMsg);
    } finally {
      process.env.NODE_ENV = origEnv;
    }
  });

  it("returns error message in non-production", () => {
    // test env is set by setup.ts
    const result = sanitizeErrorMessage(new Error("detailed info"), defaultMsg);
    expect(result).toBe("detailed info");
  });

  it("returns default message when error has no message in non-production", () => {
    const result = sanitizeErrorMessage(null, defaultMsg);
    expect(result).toBe(defaultMsg);
  });
});

// ─── needsReAuth ───────────────────────────────────────────────────────────────

describe("needsReAuth", () => {
  it.each([
    "re-authenticate",
    "Refresh token not available",
    "User not found",
    "Token is invalid",
    "Token expired",
  ])("returns true for error message containing \"%s\"", (msg) => {
    expect(needsReAuth(new Error(msg))).toBe(true);
    expect(needsReAuth(msg)).toBe(true);
  });

  it("returns false for unrelated error messages", () => {
    expect(needsReAuth(new Error("Network timeout"))).toBe(false);
    expect(needsReAuth("Some other error")).toBe(false);
  });

  it("returns false for null/undefined", () => {
    expect(needsReAuth(null)).toBe(false);
    expect(needsReAuth(undefined)).toBe(false);
  });
});

// ─── handleApiError ────────────────────────────────────────────────────────────

describe("handleApiError", () => {
  let mockRes: { status: jest.Mock; json: jest.Mock };

  beforeEach(() => {
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
  });

  it("sends a 500 response by default", () => {
    handleApiError(mockRes as any, new Error("db failed"), "Internal error");
    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      success: false,
      message: expect.any(String),
    });
  });

  it("uses the specified status code", () => {
    handleApiError(mockRes as any, new Error("bad"), "Bad request", 400);
    expect(mockRes.status).toHaveBeenCalledWith(400);
  });

  it("sanitizes the error message in the response", () => {
    handleApiError(mockRes as any, new Error("detail"), "Fallback msg");
    // In test env (non-production), returns actual error message
    expect(mockRes.json).toHaveBeenCalledWith({
      success: false,
      message: "detail",
    });
  });
});

// ─── redirectToFrontendWithError ───────────────────────────────────────────────

describe("redirectToFrontendWithError", () => {
  let mockRes: { redirect: jest.Mock; status: jest.Mock; send: jest.Mock };

  beforeEach(() => {
    mockRes = {
      redirect: jest.fn(),
      status: jest.fn().mockReturnThis(),
      send: jest.fn(),
    };
  });

  it("redirects to auth-error page with error params", () => {
    redirectToFrontendWithError(mockRes as any, "auth_failed", "Login failed");
    expect(mockRes.redirect).toHaveBeenCalledWith(
      expect.stringContaining("/auth-error.html"),
    );
    expect(mockRes.redirect).toHaveBeenCalledWith(
      expect.stringContaining("error=auth_failed"),
    );
    expect(mockRes.redirect).toHaveBeenCalledWith(
      expect.stringContaining("error_description=Login+failed"),
    );
  });

  it("includes frontendRedirect from parsed state", () => {
    const state = JSON.stringify({ frontendRedirect: "/dashboard" });
    redirectToFrontendWithError(mockRes as any, "err", "msg", state);
    expect(mockRes.redirect).toHaveBeenCalledWith(
      expect.stringContaining("frontendRedirect=%2Fdashboard"),
    );
  });

  it("handles invalid state JSON gracefully", () => {
    redirectToFrontendWithError(mockRes as any, "err", "msg", "not-json");
    // Should still redirect, just without frontendRedirect
    expect(mockRes.redirect).toHaveBeenCalled();
  });

  it("handles null state", () => {
    redirectToFrontendWithError(mockRes as any, "err", "msg", null);
    expect(mockRes.redirect).toHaveBeenCalled();
  });
});

// ─── Custom Error Classes ──────────────────────────────────────────────────────

describe("AuthError", () => {
  it("creates error with correct name and default status code", () => {
    const error = new AuthError("Unauthorized");
    expect(error.name).toBe("AuthError");
    expect(error.message).toBe("Unauthorized");
    expect(error.statusCode).toBe(401);
    expect(error).toBeInstanceOf(Error);
  });

  it("accepts a custom status code", () => {
    const error = new AuthError("Not found", 404);
    expect(error.statusCode).toBe(404);
  });
});

describe("ValidationError", () => {
  it("creates error with correct name", () => {
    const error = new ValidationError("Invalid input");
    expect(error.name).toBe("ValidationError");
    expect(error.message).toBe("Invalid input");
    expect(error).toBeInstanceOf(Error);
  });
});

describe("TwitchApiError", () => {
  it("creates error with correct name and optional properties", () => {
    const twitchData = { status: 429, message: "Too many requests" };
    const error = new TwitchApiError("Rate limited", 429, twitchData);
    expect(error.name).toBe("TwitchApiError");
    expect(error.message).toBe("Rate limited");
    expect(error.statusCode).toBe(429);
    expect(error.twitchError).toBe(twitchData);
    expect(error).toBeInstanceOf(Error);
  });

  it("works without optional properties", () => {
    const error = new TwitchApiError("API error");
    expect(error.statusCode).toBeUndefined();
    expect(error.twitchError).toBeUndefined();
  });
});
