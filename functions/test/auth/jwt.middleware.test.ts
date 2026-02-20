/**
 * Tests for auth/jwt.middleware.ts
 * JWT authentication middleware and session token creation
 */

import jwt from "jsonwebtoken";
import { authenticateApiRequest, createSessionToken } from "@/auth/jwt.middleware";

// Mock dependencies
jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

// Use the test JWT_SECRET from setup.ts env
const JWT_SECRET = process.env.JWT_SECRET_KEY!;

describe("authenticateApiRequest", () => {
  let mockReq: any;
  let mockRes: any;
  let mockNext: jest.Mock;

  beforeEach(() => {
    mockReq = {
      headers: {},
      path: "/api/test",
      method: "GET",
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockNext = jest.fn();
  });

  it("returns 401 when no Authorization header is present", () => {
    authenticateApiRequest(mockReq, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      success: false,
      message: "Unauthorized: Missing token",
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("returns 401 for malformed Authorization header", () => {
    mockReq.headers.authorization = "Token abc123";
    authenticateApiRequest(mockReq, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("returns 401 for invalid JWT", () => {
    mockReq.headers.authorization = "Bearer invalid.token.here";
    authenticateApiRequest(mockReq, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      success: false,
      message: "Unauthorized: Invalid token",
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("returns 401 for token with missing required fields", () => {
    const token = jwt.sign({ login: "testuser" }, JWT_SECRET); // missing userId
    mockReq.headers.authorization = `Bearer ${token}`;
    authenticateApiRequest(mockReq, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it("attaches user to request and calls next for valid token", () => {
    const payload = {
      login: "testuser",
      userId: "123456",
      displayName: "TestUser",
      email: "test@example.com",
    };
    const token = jwt.sign(payload, JWT_SECRET);
    mockReq.headers.authorization = `Bearer ${token}`;

    authenticateApiRequest(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockReq.user).toBeDefined();
    expect(mockReq.user.login).toBe("testuser");
    expect(mockReq.user.userId).toBe("123456");
    expect(mockReq.user.displayName).toBe("TestUser");
    expect(mockReq.user.email).toBe("test@example.com");
  });

  it("handles missing email in token payload", () => {
    const payload = {
      login: "testuser",
      userId: "123456",
      displayName: "TestUser",
    };
    const token = jwt.sign(payload, JWT_SECRET);
    mockReq.headers.authorization = `Bearer ${token}`;

    authenticateApiRequest(mockReq, mockRes, mockNext);

    expect(mockNext).toHaveBeenCalled();
    expect(mockReq.user.email).toBeNull();
  });

  it("returns 401 for expired token", () => {
    const payload = {
      login: "testuser",
      userId: "123456",
      displayName: "TestUser",
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "0s" });
    mockReq.headers.authorization = `Bearer ${token}`;

    // Small delay to ensure token is expired
    authenticateApiRequest(mockReq, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockNext).not.toHaveBeenCalled();
  });
});

describe("createSessionToken", () => {
  it("creates a valid JWT token with user data", () => {
    const user = {
      login: "testuser",
      userId: "123456",
      displayName: "TestUser",
      email: "test@example.com",
    };

    const token = createSessionToken(user);
    const decoded = jwt.verify(token, JWT_SECRET) as any;

    expect(decoded.login).toBe("testuser");
    expect(decoded.userId).toBe("123456");
    expect(decoded.displayName).toBe("TestUser");
    expect(decoded.email).toBe("test@example.com");
  });

  it("sets null email when email is not provided", () => {
    const user = {
      login: "testuser",
      userId: "123456",
      displayName: "TestUser",
    };

    const token = createSessionToken(user);
    const decoded = jwt.verify(token, JWT_SECRET) as any;

    expect(decoded.email).toBeNull();
  });

  it("uses default 7-day expiry", () => {
    const user = {
      login: "testuser",
      userId: "123456",
      displayName: "TestUser",
    };

    const token = createSessionToken(user);
    const decoded = jwt.verify(token, JWT_SECRET) as any;

    // Should expire approximately 7 days from now
    const expectedExpiry = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60;
    expect(decoded.exp).toBeCloseTo(expectedExpiry, -1); // within ~10 seconds
  });

  it("supports custom expiry", () => {
    const user = {
      login: "testuser",
      userId: "123456",
      displayName: "TestUser",
    };

    const token = createSessionToken(user, "1h");
    const decoded = jwt.verify(token, JWT_SECRET) as any;

    const expectedExpiry = Math.floor(Date.now() / 1000) + 3600;
    expect(decoded.exp).toBeCloseTo(expectedExpiry, -1);
  });
});
