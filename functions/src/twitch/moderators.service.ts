/**
 * Twitch moderators service
 * Functions for managing channel moderators
 */

import axios from "axios";
import { TWITCH_CLIENT_ID } from "@/config/constants";
import { logger } from "@/config/logger";
import { getValidTwitchTokenForUser } from "@/tokens";

export interface ModeratorResult {
  success: boolean;
  error?: string;
}

/**
 * Adds a user as a moderator in a broadcaster's channel
 * @param broadcasterLogin - The broadcaster's Twitch login
 * @param broadcasterId - The broadcaster's Twitch user ID
 * @param moderatorUserId - The user ID to add as moderator
 * @returns Success status and optional error message
 */
export async function addModerator(
  broadcasterLogin: string,
  broadcasterId: string,
  moderatorUserId: string,
): Promise<ModeratorResult> {
  try {
    const accessToken = await getValidTwitchTokenForUser(broadcasterLogin);

    const response = await axios.post(
      "https://api.twitch.tv/helix/moderation/moderators",
      {},
      {
        params: {
          broadcaster_id: broadcasterId,
          user_id: moderatorUserId,
        },
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Client-Id": TWITCH_CLIENT_ID,
        },
        timeout: 15000,
      },
    );

    // 204 No Content means success
    if (response.status === 204) {
      logger.info("Successfully added moderator", {
        broadcasterLogin,
        moderatorUserId,
      });
      return { success: true };
    }

    return {
      success: false,
      error: `Unexpected status: ${response.status}`,
    };
  } catch (error: unknown) {
    const err = error as {
      response?: {
        status?: number;
        data?: { message?: string };
      };
      message: string;
    };
    const status = err.response?.status;
    const errorData = err.response?.data;
    const errorMessage = errorData?.message || err.message;

    // 400 Bad Request - could be: already moderator, banned, or VIP
    if (status === 400) {
      if (
        errorMessage?.toLowerCase().includes("already") ||
        errorMessage?.toLowerCase().includes("moderator")
      ) {
        logger.info("User is already a moderator", {
          broadcasterLogin,
          moderatorUserId,
        });
        return { success: true }; // Already a mod, treat as success
      }

      logger.warn("Cannot add moderator", {
        broadcasterLogin,
        moderatorUserId,
        error: errorMessage,
      });
      return {
        success: false,
        error: errorMessage || "User cannot be added as moderator (may be banned or VIP)",
      };
    }

    // 403 Forbidden - broadcaster doesn't have channel:manage:moderators scope
    if (status === 403) {
      logger.warn("Broadcaster lacks required scope", {
        broadcasterLogin,
      });
      return {
        success: false,
        error: "Missing channel:manage:moderators scope. Please re-authenticate.",
      };
    }

    // 401 Unauthorized - token invalid or expired
    if (status === 401) {
      logger.warn("Authentication failed", {
        broadcasterLogin,
      });
      return {
        success: false,
        error: "Authentication failed. Please re-authenticate.",
      };
    }

    // 404 Not Found - user or broadcaster doesn't exist
    if (status === 404) {
      logger.warn("User or broadcaster not found");
      return {
        success: false,
        error: "User or broadcaster not found",
      };
    }

    // Other errors
    logger.error("Error adding moderator", {
      broadcasterLogin,
      moderatorUserId,
      status,
      error: errorMessage,
    });
    return {
      success: false,
      error: errorMessage || "Unknown error occurred",
    };
  }
}
