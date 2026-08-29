/**
 * Twitch channels service
 * Reads channel information the dashboard needs from Helix.
 */

import axios from "axios";
import { TWITCH_CLIENT_ID } from "@/config/constants";
import { logger } from "@/config/logger";
import { redact } from "@/utils/redact";
import { getAppAccessToken } from "./appToken.service";

/**
 * Reads the stream language the broadcaster set on their Twitch channel.
 *
 * The bot uses this value as the default bot language when nobody has chosen one, so the dashboard
 * shows it to explain what the automatic setting resolves to.
 *
 * @param broadcasterId - Twitch user ID of the channel.
 * @returns The two-letter language code, or null when it is unknown or unreadable.
 */
export async function getChannelStreamLanguage(broadcasterId: string): Promise<string | null> {
  try {
    const appAccessToken = await getAppAccessToken();

    const response = await axios.get("https://api.twitch.tv/helix/channels", {
      params: { broadcaster_id: broadcasterId },
      headers: {
        "Client-Id": TWITCH_CLIENT_ID,
        "Authorization": `Bearer ${appAccessToken}`,
      },
      timeout: 15000,
    });

    const language = response.data?.data?.[0]?.broadcaster_language;
    return typeof language === "string" && language.trim() ? language.trim().toLowerCase() : null;
  } catch (error: unknown) {
    const err = error as { response?: { data?: unknown }; message: string };
    // Never fatal: the language setting still works, it just cannot name the detected language.
    logger.warn("Could not read channel stream language", {
      broadcasterId: redact(broadcasterId),
      error: err.response?.data || err.message,
    });
    return null;
  }
}
