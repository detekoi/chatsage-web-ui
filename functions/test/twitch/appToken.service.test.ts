/**
 * Tests for twitch/appToken.service.ts
 * App access token management with caching
 */

import axios from "axios";
import { getAppAccessToken, clearAppAccessTokenCache } from "@/twitch/appToken.service";

jest.mock("axios");
jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

const mockAxios = axios as jest.Mocked<typeof axios>;

describe("getAppAccessToken", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearAppAccessTokenCache();
  });

  it("fetches a new app access token from Twitch", async () => {
    mockAxios.post.mockResolvedValueOnce({
      data: {
        access_token: "app-token-123",
        expires_in: 5000000,
        token_type: "bearer",
      },
    });

    const token = await getAppAccessToken();
    expect(token).toBe("app-token-123");
    expect(mockAxios.post).toHaveBeenCalledTimes(1);
  });

  it("returns cached token on subsequent calls", async () => {
    mockAxios.post.mockResolvedValueOnce({
      data: {
        access_token: "cached-app-token",
        expires_in: 5000000,
        token_type: "bearer",
      },
    });

    const token1 = await getAppAccessToken();
    const token2 = await getAppAccessToken();

    expect(token1).toBe("cached-app-token");
    expect(token2).toBe("cached-app-token");
    expect(mockAxios.post).toHaveBeenCalledTimes(1);
  });

  it("throws when Twitch API call fails", async () => {
    mockAxios.post.mockRejectedValueOnce(new Error("Network error"));

    await expect(getAppAccessToken()).rejects.toThrow();
  });
});

describe("clearAppAccessTokenCache", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearAppAccessTokenCache();
  });

  it("forces a fresh fetch on next call", async () => {
    mockAxios.post.mockResolvedValue({
      data: {
        access_token: "token",
        expires_in: 5000000,
        token_type: "bearer",
      },
    });

    await getAppAccessToken();
    clearAppAccessTokenCache();
    await getAppAccessToken();

    expect(mockAxios.post).toHaveBeenCalledTimes(2);
  });
});
