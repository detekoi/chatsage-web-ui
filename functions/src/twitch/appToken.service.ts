/**
 * App access token service
 * Manages Twitch app access tokens for EventSub and other app-level API calls
 */

import axios from "axios";
import { TWITCH_CLIENT_ID, TWITCH_CLIENT_SECRET, APP_TOKEN_REFRESH_BUFFER_MS } from "@/config/constants";
import { logger } from "@/config/logger";

// Cache for app access token (these last 60 days but we refresh with buffer)
let appAccessTokenCache: string | null = null;
let appAccessTokenExpiry = 0;

/**
 * Gets an app access token (with caching)
 * Used for EventSub subscriptions and other app-level operations
 *
 * @returns App access token
 */
export async function getAppAccessToken(): Promise<string> {
  // Return cached token if still valid (with 1 hour buffer)
  if (appAccessTokenCache && Date.now() < appAccessTokenExpiry - APP_TOKEN_REFRESH_BUFFER_MS) {
    logger.debug("Using cached app access token");
    return appAccessTokenCache;
  }

  logger.info("Fetching new app access token");

  // Get new app access token using client credentials flow
  try {
    const response = await axios.post("https://id.twitch.tv/oauth2/token", null, {
      params: {
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        grant_type: "client_credentials",
      },
    });

    appAccessTokenCache = response.data.access_token;
    const expiresIn = response.data.expires_in || 5184000; // Default 60 days
    appAccessTokenExpiry = Date.now() + (expiresIn * 1000);

    logger.info("Obtained new app access token", {
      expiresInDays: Math.floor(expiresIn / 86400),
    });

    if (!appAccessTokenCache) {
      throw new Error("Failed to obtain app access token from Twitch");
    }

    return appAccessTokenCache;
  } catch (error: unknown) {
    const err = error as Error;
    logger.error("Failed to get app access token", {
      error: err.message,
    });
    throw error;
  }
}

/**
 * Clears the app access token cache
 * Useful for testing or forcing refresh
 */
export function clearAppAccessTokenCache(): void {
  appAccessTokenCache = null;
  appAccessTokenExpiry = 0;
  logger.debug("Cleared app access token cache");
}
