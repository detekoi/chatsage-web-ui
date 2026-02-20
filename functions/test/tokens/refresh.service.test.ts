/**
 * Tests for tokens/refresh.service.ts
 * Token refresh and validation with Twitch API
 */

import axios from "axios";
import { refreshTwitchToken, validateAccessToken } from "@/tokens/refresh.service";

// Mock dependencies
jest.mock("axios");
jest.mock("@/config/logger", () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock constants to use 0ms retry delay for test speed
jest.mock("@/config/constants", () => ({
  TWITCH_CLIENT_ID: "test-client-id",
  TWITCH_CLIENT_SECRET: "test-client-secret",
  TWITCH_TOKEN_URL: "https://id.twitch.tv/oauth2/token",
  TWITCH_VALIDATE_URL: "https://id.twitch.tv/oauth2/validate",
  TOKEN_REFRESH: {
    MAX_RETRY_ATTEMPTS: 3,
    RETRY_DELAY_MS: 0, // No delay in tests
  },
}));

const mockAxios = axios as jest.Mocked<typeof axios>;

describe("refreshTwitchToken", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("returns new tokens on successful refresh and validation", async () => {
    // Token refresh call
    mockAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        access_token: "new-access-token",
        refresh_token: "new-refresh-token",
        expires_in: 3600,
      },
    });
    // Validation call
    mockAxios.get.mockResolvedValueOnce({ status: 200 });

    const result = await refreshTwitchToken("old-refresh-token");

    expect(result).toEqual({
      accessToken: "new-access-token",
      refreshToken: "new-refresh-token",
      expiresIn: 3600,
    });
  });

  it("uses current refresh token when new one is not provided", async () => {
    mockAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        access_token: "new-access",
        refresh_token: null,
        expires_in: 3600,
      },
    });
    mockAxios.get.mockResolvedValueOnce({ status: 200 });

    const result = await refreshTwitchToken("original-token");
    expect(result.refreshToken).toBe("original-token");
  });

  it("defaults expiresIn to 3600 if not provided", async () => {
    mockAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        access_token: "token",
        refresh_token: "refresh",
        expires_in: null,
      },
    });
    mockAxios.get.mockResolvedValueOnce({ status: 200 });

    const result = await refreshTwitchToken("refresh-token");
    expect(result.expiresIn).toBe(3600);
  });

  it("throws TwitchApiError without retrying on 400 (invalid refresh token)", async () => {
    mockAxios.post.mockRejectedValueOnce({
      response: { status: 400, data: { message: "Invalid refresh token" } },
      message: "Request failed",
    });

    await expect(refreshTwitchToken("bad-token")).rejects.toThrow(
      "Refresh token is invalid or expired",
    );

    // Should not have retried
    expect(mockAxios.post).toHaveBeenCalledTimes(1);
  });

  it("throws TwitchApiError without retrying on 401", async () => {
    mockAxios.post.mockRejectedValueOnce({
      response: { status: 401, data: {} },
      message: "Unauthorized",
    });

    await expect(refreshTwitchToken("expired-token")).rejects.toThrow(
      "Refresh token is invalid or expired",
    );
    expect(mockAxios.post).toHaveBeenCalledTimes(1);
  });

  it("retries on server errors and eventually throws", async () => {
    const serverError = {
      response: { status: 500, data: { message: "Internal Server Error" } },
      message: "Server error",
    };
    mockAxios.post
      .mockRejectedValueOnce(serverError)
      .mockRejectedValueOnce(serverError)
      .mockRejectedValueOnce(serverError);

    await expect(refreshTwitchToken("token")).rejects.toThrow();
    expect(mockAxios.post).toHaveBeenCalledTimes(3);
  });

  it("throws TwitchApiError when validation of refreshed token fails", async () => {
    // First attempt: post succeeds but validation fails
    mockAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        access_token: "bad-access-token",
        refresh_token: "new-refresh",
        expires_in: 3600,
      },
    });
    mockAxios.get.mockRejectedValueOnce(new Error("Validation failed"));

    // Subsequent retry attempts also fail (validation throws are retried)
    mockAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        access_token: "bad-2",
        refresh_token: "refresh-2",
        expires_in: 3600,
      },
    });
    mockAxios.get.mockRejectedValueOnce(new Error("Validation failed again"));

    mockAxios.post.mockResolvedValueOnce({
      status: 200,
      data: {
        access_token: "bad-3",
        refresh_token: "refresh-3",
        expires_in: 3600,
      },
    });
    mockAxios.get.mockRejectedValueOnce(new Error("Validation failed third"));

    await expect(refreshTwitchToken("refresh-token")).rejects.toThrow(
      "Refreshed token validation failed",
    );
  });
});

describe("validateAccessToken", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("returns true for a valid token", async () => {
    mockAxios.get.mockResolvedValueOnce({ status: 200 });
    const result = await validateAccessToken("valid-token");
    expect(result).toBe(true);
  });

  it("returns false for an invalid token", async () => {
    mockAxios.get.mockRejectedValueOnce(new Error("401 Unauthorized"));
    const result = await validateAccessToken("invalid-token");
    expect(result).toBe(false);
  });
});
