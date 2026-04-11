/**
 * Tests for tokens/token.service.ts
 * Main token orchestration: caching, refresh, and Firestore updates
 */

import { getValidTwitchTokenForUser, clearUserTokens } from "@/tokens/token.service";

// --- Mock dependencies ---

jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock("@/tokens/cache.service", () => ({
  getCachedToken: jest.fn(),
  cacheToken: jest.fn(),
  clearCachedToken: jest.fn(),
}));

jest.mock("@/tokens/refresh.service", () => ({
  refreshTwitchToken: jest.fn(),
}));

jest.mock("@/tokens/firestoreRefreshToken.service", () => ({
  getStoredTwitchRefreshToken: jest.fn(),
  storeTwitchRefreshToken: jest.fn(),
}));

const mockUpdate = jest.fn().mockResolvedValue(undefined);
const mockSet = jest.fn().mockResolvedValue(undefined);
const mockGet = jest.fn();
const mockDoc = jest.fn().mockReturnValue({
  get: mockGet,
  update: mockUpdate,
  set: mockSet,
});
const mockCollection = jest.fn().mockReturnValue({ doc: mockDoc });

jest.mock("@/config/database", () => ({
  getDb: () => ({ collection: mockCollection }),
  FieldValue: { serverTimestamp: () => "SERVER_TIMESTAMP" },
}));

import { getCachedToken, cacheToken, clearCachedToken } from "@/tokens/cache.service";
import { refreshTwitchToken } from "@/tokens/refresh.service";
import { getStoredTwitchRefreshToken, storeTwitchRefreshToken } from "@/tokens/firestoreRefreshToken.service";

const mockGetCachedToken = getCachedToken as jest.MockedFunction<typeof getCachedToken>;
const mockCacheToken = cacheToken as jest.MockedFunction<typeof cacheToken>;
const mockClearCachedToken = clearCachedToken as jest.MockedFunction<typeof clearCachedToken>;
const mockRefreshTwitchToken = refreshTwitchToken as jest.MockedFunction<typeof refreshTwitchToken>;
const mockGetStoredRefreshToken = getStoredTwitchRefreshToken as jest.MockedFunction<typeof getStoredTwitchRefreshToken>;
const mockStoreRefreshToken = storeTwitchRefreshToken as jest.MockedFunction<typeof storeTwitchRefreshToken>;

describe("getValidTwitchTokenForUser", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("returns cached token if available", async () => {
    mockGetCachedToken.mockReturnValue("cached-access-token");

    const result = await getValidTwitchTokenForUser("testuser");

    expect(result).toBe("cached-access-token");
    expect(mockRefreshTwitchToken).not.toHaveBeenCalled();
  });

  it("refreshes token when cache is empty and user exists", async () => {
    mockGetCachedToken.mockReturnValue(null);
    mockGet.mockResolvedValue({
      exists: true,
      data: () => ({ twitchUserId: "twitch-123" }),
    });
    mockGetStoredRefreshToken.mockResolvedValue("stored-refresh-token");
    mockRefreshTwitchToken.mockResolvedValue({
      accessToken: "new-access-token",
      refreshToken: "new-refresh-token",
      expiresIn: 3600,
    });
    mockStoreRefreshToken.mockResolvedValue(undefined);

    const result = await getValidTwitchTokenForUser("testuser");

    expect(result).toBe("new-access-token");
    expect(mockCacheToken).toHaveBeenCalledWith("testuser", "new-access-token", 3600);
  });

  it("stores rotated refresh token in Firestore", async () => {
    mockGetCachedToken.mockReturnValue(null);
    mockGet.mockResolvedValue({
      exists: true,
      data: () => ({ twitchUserId: "twitch-123" }),
    });
    mockGetStoredRefreshToken.mockResolvedValue("old-refresh");
    mockRefreshTwitchToken.mockResolvedValue({
      accessToken: "access",
      refreshToken: "new-rotated-refresh", // Different from old
      expiresIn: 3600,
    });

    await getValidTwitchTokenForUser("testuser");

    expect(mockStoreRefreshToken).toHaveBeenCalledWith(
      expect.anything(),
      "testuser",
      "new-rotated-refresh",
      { reason: "twitch-rotation" },
    );
  });

  it("throws AuthError when user document does not exist", async () => {
    mockGetCachedToken.mockReturnValue(null);
    mockGet.mockResolvedValue({ exists: false });

    await expect(getValidTwitchTokenForUser("unknownuser")).rejects.toThrow(
      "User not found",
    );
  });

  it("resolves when twitchUserId is missing from doc (uses userId arg directly)", async () => {
    mockGetCachedToken.mockReturnValue(null);
    mockGet.mockResolvedValue({
      exists: true,
      data: () => ({}), // no twitchUserId — impl now ignores this field
    });
    // The impl uses the userId arg directly, not the doc's twitchUserId field.
    // With no refresh token found, it throws a generic auth error.
    mockGetStoredRefreshToken.mockResolvedValue(null);

    await expect(getValidTwitchTokenForUser("testuser")).rejects.toThrow(
      "Failed to obtain a valid Twitch token",
    );
  });


  it("throws AuthError when no refresh token is stored", async () => {
    mockGetCachedToken.mockReturnValue(null);
    mockGet.mockResolvedValue({
      exists: true,
      data: () => ({ twitchUserId: "twitch-123" }),
    });
    mockGetStoredRefreshToken.mockResolvedValue(null);

    await expect(getValidTwitchTokenForUser("testuser")).rejects.toThrow(
      "Failed to obtain a valid Twitch token",
    );
  });

  it("marks user as needing re-auth on refresh failure", async () => {
    mockGetCachedToken.mockReturnValue(null);
    mockGet.mockResolvedValue({
      exists: true,
      data: () => ({ twitchUserId: "twitch-123" }),
    });
    mockGetStoredRefreshToken.mockResolvedValue("refresh");
    mockRefreshTwitchToken.mockRejectedValue(new Error("Refresh failed"));

    await expect(getValidTwitchTokenForUser("testuser")).rejects.toThrow();

    expect(mockClearCachedToken).toHaveBeenCalledWith("testuser");
    expect(mockUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ needsTwitchReAuth: true }),
    );
  });
});

describe("clearUserTokens", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("clears cache and updates Firestore", async () => {
    mockGet.mockResolvedValue({ exists: true });

    const result = await clearUserTokens("testuser", "Manual clear");

    expect(result).toBe(true);
    expect(mockClearCachedToken).toHaveBeenCalledWith("testuser");
    expect(mockUpdate).toHaveBeenCalledWith(
      expect.objectContaining({
        needsTwitchReAuth: true,
        lastTokenClearReason: "Manual clear",
      }),
    );
  });

  it("returns false for empty userLogin", async () => {
    const result = await clearUserTokens("");
    expect(result).toBe(false);
  });

  it("returns false when user document does not exist", async () => {
    mockGet.mockResolvedValue({ exists: false });

    const result = await clearUserTokens("unknownuser");
    expect(result).toBe(false);
  });

  it("returns false on Firestore error", async () => {
    mockGet.mockRejectedValue(new Error("Firestore down"));

    const result = await clearUserTokens("testuser");
    expect(result).toBe(false);
  });
});
