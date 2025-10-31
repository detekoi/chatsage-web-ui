/**
 * Twitch EventSub service
 * Manages EventSub webhook subscriptions (e.g., ad break notifications)
 */

import axios from "axios";
import { getDb } from "@/config/database";
import {
  TWITCH_CLIENT_ID,
  TWITCH_HELIX_URL,
  CHANNELS_COLLECTION,
  BOT_PUBLIC_URL,
  TWITCH_EVENTSUB_SECRET,
} from "@/config/constants";
import { logger } from "@/config/logger";
import { getValidTwitchTokenForUser } from "@/tokens";
import { getAppAccessToken } from "./appToken.service";

/**
 * Ensures an ad break EventSub subscription exists or is removed
 * @param channelLogin - Channel login name
 * @param adsEnabled - Whether ads notifications should be enabled
 */
export async function ensureAdBreakSubscription(
  channelLogin: string,
  adsEnabled: boolean,
): Promise<void> {
  if (!BOT_PUBLIC_URL) {
    logger.warn("BOT_PUBLIC_URL not configured, skipping EventSub setup");
    return;
  }

  try {
    const db = getDb();

    // Get user ID from Firestore
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
    const userDoc = await userDocRef.get();
    const userId = userDoc.exists ? userDoc.data()?.twitchUserId : null;

    if (!userId) {
      logger.warn("No user ID found for channel", { channelLogin });
      return;
    }

    // Verify user has granted channel:read:ads scope
    try {
      const userToken = await getValidTwitchTokenForUser(channelLogin);
      const validateResponse = await axios.get("https://id.twitch.tv/oauth2/validate", {
        headers: { Authorization: `OAuth ${userToken}` },
      });

      const scopes = validateResponse.data.scopes || [];
      logger.debug("User token validation", {
        channelLogin,
        userId: validateResponse.data.user_id,
        hasAdsScope: scopes.includes("channel:read:ads"),
      });

      if (!scopes.includes("channel:read:ads")) {
        logger.error("User hasn't granted channel:read:ads scope", {
          channelLogin,
        });
        return;
      }
    } catch (validateErr: unknown) {
      const err = validateErr as Error;
      logger.error("User token validation failed", {
        channelLogin,
        error: err.message,
      });
      return;
    }

    // Use APP access token for EventSub webhook subscription (required by Twitch)
    const appAccessToken = await getAppAccessToken();
    logger.debug("Using app access token for EventSub", {
      channelLogin,
    });

    const headers = {
      Authorization: `Bearer ${appAccessToken}`,
      "Client-ID": TWITCH_CLIENT_ID,
      "Content-Type": "application/json",
    };

    // Check existing subscriptions
    const list = await axios.get(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, {
      headers,
    });

    const existing = (list.data?.data || []).filter(
      (s: { type: string; condition?: { broadcaster_user_id?: string } }) =>
        s.type === "channel.ad_break.begin" &&
        s.condition?.broadcaster_user_id === String(userId),
    );

    if (adsEnabled) {
      // Create subscription if it doesn't exist
      if (existing.length > 0) {
        logger.info("Ad break subscription already exists", {
          channelLogin,
          subscriptionCount: existing.length,
        });
        return;
      }

      const body = {
        type: "channel.ad_break.begin",
        version: "1",
        condition: { broadcaster_user_id: String(userId) },
        transport: {
          method: "webhook",
          callback: `${BOT_PUBLIC_URL}/twitch/event`,
          secret: TWITCH_EVENTSUB_SECRET,
        },
      };

      logger.info("Creating ad break subscription", {
        channelLogin,
        userId,
      });

      await axios.post(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, body, {
        headers,
      });

      logger.info("Ad break subscription created", { channelLogin });
    } else {
      // Delete existing subscriptions
      for (const sub of existing) {
        await axios.delete(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, {
          headers,
          params: { id: (sub as { id: string }).id },
        });

        logger.info("Deleted ad break subscription", {
          channelLogin,
          subscriptionId: (sub as { id: string }).id,
        });
      }
    }
  } catch (error: unknown) {
    const err = error as {
      response?: {
        status?: number;
        statusText?: string;
        data?: unknown;
      };
      message: string;
    };

    logger.error("Error managing ad break subscription", {
      channelLogin,
      adsEnabled,
      message: err.message,
      status: err.response?.status,
      statusText: err.response?.statusText,
      twitchError: err.response?.data,
    });

    throw err;
  }
}
