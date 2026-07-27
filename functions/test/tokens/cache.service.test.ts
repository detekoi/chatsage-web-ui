/**
 * Tests for tokens/cache.service.ts
 * Firestore-backed token caching service (shared across instances)
 */

import {
  getCachedToken,
  cacheToken,
  clearCachedToken,
} from "@/tokens/cache.service";

// Mock dependencies
jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

const mockGet = jest.fn();
const mockSet = jest.fn();

jest.mock("@/config/database", () => ({
  getDb: jest.fn(() => ({})),
  FieldValue: {
    serverTimestamp: jest.fn(() => "SERVER_TIMESTAMP"),
    delete: jest.fn(() => "DELETE_SENTINEL"),
  },
}));

jest.mock("@/tokens/firestoreRefreshToken.service", () => ({
  getOauthDocRef: jest.fn(() => ({
    get: mockGet,
    set: mockSet,
  })),
}));

describe("Token Cache Service", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSet.mockResolvedValue(undefined);
  });

  describe("getCachedToken", () => {
    it("returns a cached token that has not expired", async () => {
      mockGet.mockResolvedValue({
        data: () => ({
          cachedAccessToken: "access-token-123",
          accessTokenExpiresAt: Date.now() + 60_000,
        }),
      });

      await expect(getCachedToken("testuser")).resolves.toBe("access-token-123");
    });

    it("returns null when no token is stored", async () => {
      mockGet.mockResolvedValue({ data: () => undefined });

      await expect(getCachedToken("unknownuser")).resolves.toBeNull();
    });

    it("returns null for an expired token", async () => {
      mockGet.mockResolvedValue({
        data: () => ({
          cachedAccessToken: "expired-token",
          accessTokenExpiresAt: Date.now() - 1_000,
        }),
      });

      await expect(getCachedToken("testuser")).resolves.toBeNull();
    });

    it("returns null when the expiry field is malformed", async () => {
      mockGet.mockResolvedValue({
        data: () => ({
          cachedAccessToken: "token",
          accessTokenExpiresAt: "not-a-number",
        }),
      });

      await expect(getCachedToken("testuser")).resolves.toBeNull();
    });

    it("fails open and returns null when Firestore read fails", async () => {
      mockGet.mockRejectedValue(new Error("firestore unavailable"));

      await expect(getCachedToken("testuser")).resolves.toBeNull();
    });
  });

  describe("cacheToken", () => {
    it("writes the token with a buffered expiry", async () => {
      const before = Date.now();
      await cacheToken("testuser", "token", 3600);

      expect(mockSet).toHaveBeenCalledTimes(1);
      const [payload, options] = mockSet.mock.calls[0];

      expect(payload.cachedAccessToken).toBe("token");
      expect(options).toEqual({ merge: true });

      // 3600s minus the 300s buffer
      expect(payload.accessTokenExpiresAt).toBeGreaterThanOrEqual(before + 3300 * 1000);
      expect(payload.accessTokenExpiresAt).toBeLessThanOrEqual(Date.now() + 3300 * 1000);
    });

    it("does not throw when the write fails", async () => {
      mockSet.mockRejectedValue(new Error("write failed"));

      await expect(cacheToken("testuser", "token", 3600)).resolves.toBeUndefined();
    });

    it("produces an already-expired entry when expiresIn equals the buffer", async () => {
      await cacheToken("testuser", "token", 300);

      const [payload] = mockSet.mock.calls[0];
      expect(payload.accessTokenExpiresAt).toBeLessThanOrEqual(Date.now());
    });
  });

  describe("clearCachedToken", () => {
    it("deletes the cached token fields and reports success", async () => {
      await expect(clearCachedToken("user1")).resolves.toBe(true);

      const [payload, options] = mockSet.mock.calls[0];
      expect(payload.cachedAccessToken).toBe("DELETE_SENTINEL");
      expect(payload.accessTokenExpiresAt).toBe("DELETE_SENTINEL");
      expect(options).toEqual({ merge: true });
    });

    it("reports failure when the write fails so revocation is not assumed", async () => {
      mockSet.mockRejectedValue(new Error("write failed"));

      await expect(clearCachedToken("user1")).resolves.toBe(false);
    });
  });
});
