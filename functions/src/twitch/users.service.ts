/**
 * Twitch users service
 * Functions for looking up Twitch user information
 */

import axios from "axios";
import { TWITCH_CLIENT_ID } from "@/config/constants";
import { logger } from "@/config/logger";
import { getAppAccessToken } from "./appToken.service";

/**
 * Gets a Twitch user ID from a username (login)
 * @param username - The Twitch username
 * @returns The user ID or null if not found
 */
export async function getUserIdFromUsername(username: string): Promise<string | null> {
  try {
    const appAccessToken = await getAppAccessToken();

    const response = await axios.get("https://api.twitch.tv/helix/users", {
      params: { login: username.toLowerCase() },
      headers: {
        "Client-Id": TWITCH_CLIENT_ID,
        "Authorization": `Bearer ${appAccessToken}`,
      },
      timeout: 15000,
    });

    if (response.data?.data && response.data.data.length > 0) {
      const userId = response.data.data[0].id;
      logger.debug("Found user ID from username", {
        username,
        userId,
      });
      return userId;
    }

    logger.warn("User not found", { username });
    return null;
  } catch (error: unknown) {
    const err = error as { response?: { data?: unknown }; message: string };
    logger.error("Error getting user ID from username", {
      username,
      error: err.response?.data || err.message,
    });
    return null;
  }
}
