/**
 * Token refresh service
 * Handles refreshing Twitch access tokens using refresh tokens
 *
 * SECURITY FIXES APPLIED:
 * - No token content in logs
 * - Proper error handling
 * - Token rotation tracking
 */

import axios from "axios";
import {
  TWITCH_CLIENT_ID,
  TWITCH_CLIENT_SECRET,
  TWITCH_TOKEN_URL,
  TWITCH_VALIDATE_URL,
  TOKEN_REFRESH,
} from "@/config/constants";
import { logger } from "@/config/logger";
import { TwitchApiError } from "@/utils/errors";

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/**
 * Refreshes a Twitch access token using a refresh token
 * Includes retry logic and validation
 *
 * @param currentRefreshToken - The current refresh token
 * @returns New access token, refresh token, and expiration
 * @throws TwitchApiError if refresh fails
 */
export async function refreshTwitchToken(
  currentRefreshToken: string,
): Promise<RefreshTokenResponse> {
  if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET) {
    logger.error("Twitch client ID or secret not configured");
    throw new Error("Server configuration error for Twitch token refresh");
  }

  const { MAX_RETRY_ATTEMPTS, RETRY_DELAY_MS } = TOKEN_REFRESH;
  let lastError: Error | null = null;

  // SECURITY: Never log token content
  logger.debug("Starting token refresh", {
    hasRefreshToken: !!currentRefreshToken,
    refreshTokenLength: currentRefreshToken.length,
  });

  for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
    logger.debug("Token refresh attempt", {
      attempt,
      maxAttempts: MAX_RETRY_ATTEMPTS,
    });

    try {
      const response = await axios.post(TWITCH_TOKEN_URL, null, {
        params: {
          grant_type: "refresh_token",
          refresh_token: currentRefreshToken,
          client_id: TWITCH_CLIENT_ID,
          client_secret: TWITCH_CLIENT_SECRET,
        },
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout: 15000,
      });

      if (response.status === 200 && response.data?.access_token) {
        const { access_token, refresh_token, expires_in } = response.data;

        logger.info("Token refresh successful", {
          attempt,
          expiresIn: expires_in,
          hasNewRefreshToken: !!refresh_token,
          tokenRotated: refresh_token !== currentRefreshToken,
        });

        // Validate the new access token before returning
        try {
          await axios.get(TWITCH_VALIDATE_URL, {
            headers: { Authorization: `Bearer ${access_token}` },
            timeout: 15000,
          });

          logger.debug("Refreshed token validated successfully", { attempt });

          return {
            accessToken: access_token,
            refreshToken: refresh_token || currentRefreshToken,
            expiresIn: expires_in || 3600, // Default 1 hour if not provided
          };
        } catch (validateError: unknown) {
          const err = validateError as Error;
          logger.error("Failed to validate refreshed token", {
            attempt,
            error: err.message,
          });
          throw new TwitchApiError("Refreshed token validation failed");
        }
      } else {
        lastError = new Error(
          `Unexpected response structure. Status: ${response.status}`,
        );
        logger.warn("Token refresh attempt failed", {
          attempt,
          status: response.status,
        });
      }
    } catch (error: unknown) {
      lastError = error as Error;
      const axiosError = error as { response?: { status?: number; data?: unknown } };
      const statusCode = axiosError.response?.status;
      const errorData = axiosError.response?.data;

      logger.error("Token refresh attempt failed", {
        attempt,
        statusCode,
        errorData,
      });

      // 400 or 401 means the refresh token is invalid - don't retry
      if (statusCode === 400 || statusCode === 401) {
        logger.error("Refresh token is invalid or expired", {
          statusCode,
        });
        throw new TwitchApiError(
          "Refresh token is invalid or expired. User needs to re-authenticate.",
          statusCode,
          errorData,
        );
      }

      // Retry for other errors (rate limits, network issues, etc.)
      if (attempt < MAX_RETRY_ATTEMPTS) {
        logger.info("Retrying token refresh", {
          attempt,
          retryDelayMs: RETRY_DELAY_MS,
        });
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
      }
    }
  }

  // All attempts failed
  const finalErrorMessage =
    (lastError as { response?: { data?: { message?: string } } })?.response?.data?.message ||
    lastError?.message ||
    "Failed to refresh Twitch token after multiple attempts";

  logger.error("All token refresh attempts failed", {
    attempts: MAX_RETRY_ATTEMPTS,
    finalError: finalErrorMessage,
  });

  throw new TwitchApiError(finalErrorMessage);
}

/**
 * Validates a Twitch access token
 * @param accessToken - The access token to validate
 * @returns True if valid, false otherwise
 */
export async function validateAccessToken(accessToken: string): Promise<boolean> {
  try {
    await axios.get(TWITCH_VALIDATE_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 15000,
    });

    logger.debug("Access token validated successfully");
    return true;
  } catch (error: unknown) {
    const err = error as Error;
    logger.warn("Access token validation failed", {
      error: err.message,
    });
    return false;
  }
}
