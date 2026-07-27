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
 * Ensures stream.online and stream.offline EventSub subscriptions exist
 * These subscriptions are REQUIRED for the bot to work with LAZY_CONNECT mode
 * @param channelLogin - Channel login name
 * @param broadcasterUserId - Twitch user ID of the broadcaster
 */
export async function ensureStreamEventSubscriptions(
  channelLogin: string,
  broadcasterUserId: string,
): Promise<void> {
  if (!BOT_PUBLIC_URL) {
    logger.warn("BOT_PUBLIC_URL not configured, skipping EventSub setup", {
      channelLogin,
    });
    return;
  }

  if (!TWITCH_EVENTSUB_SECRET) {
    logger.warn("TWITCH_EVENTSUB_SECRET not configured, skipping EventSub setup", {
      channelLogin,
    });
    return;
  }

  try {
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

    const existingStreamOnline = (list.data?.data || []).filter(
      (s: { type: string; condition?: { broadcaster_user_id?: string } }) =>
        s.type === "stream.online" &&
        s.condition?.broadcaster_user_id === String(broadcasterUserId),
    );

    const existingStreamOffline = (list.data?.data || []).filter(
      (s: { type: string; condition?: { broadcaster_user_id?: string } }) =>
        s.type === "stream.offline" &&
        s.condition?.broadcaster_user_id === String(broadcasterUserId),
    );

    // Create stream.online subscription if it doesn't exist
    if (existingStreamOnline.length === 0) {
      const onlineBody = {
        type: "stream.online",
        version: "1",
        condition: { broadcaster_user_id: String(broadcasterUserId) },
        transport: {
          method: "webhook",
          callback: `${BOT_PUBLIC_URL}/twitch/event`,
          secret: TWITCH_EVENTSUB_SECRET,
        },
      };

      logger.info("Creating stream.online subscription", {
        channelLogin,
        broadcasterUserId,
      });

      await axios.post(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, onlineBody, {
        headers,
      });

      logger.info("stream.online subscription created", { channelLogin });
    } else {
      logger.info("stream.online subscription already exists", {
        channelLogin,
        subscriptionCount: existingStreamOnline.length,
      });
    }

    // Create stream.offline subscription if it doesn't exist
    if (existingStreamOffline.length === 0) {
      const offlineBody = {
        type: "stream.offline",
        version: "1",
        condition: { broadcaster_user_id: String(broadcasterUserId) },
        transport: {
          method: "webhook",
          callback: `${BOT_PUBLIC_URL}/twitch/event`,
          secret: TWITCH_EVENTSUB_SECRET,
        },
      };

      logger.info("Creating stream.offline subscription", {
        channelLogin,
        broadcasterUserId,
      });

      await axios.post(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, offlineBody, {
        headers,
      });

      logger.info("stream.offline subscription created", { channelLogin });
    } else {
      logger.info("stream.offline subscription already exists", {
        channelLogin,
        subscriptionCount: existingStreamOffline.length,
      });
    }

    logger.info("Stream event subscriptions ensured", {
      channelLogin,
      broadcasterUserId,
      streamOnlineExists: existingStreamOnline.length > 0,
      streamOfflineExists: existingStreamOffline.length > 0,
    });
  } catch (error: unknown) {
    const err = error as {
      response?: {
        status?: number;
        statusText?: string;
        data?: unknown;
      };
      message: string;
    };

    logger.error("Error ensuring stream event subscriptions", {
      channelLogin,
      broadcasterUserId,
      message: err.message,
      status: err.response?.status,
      statusText: err.response?.statusText,
      twitchError: err.response?.data,
    });

    throw err;
  }
}

/**
 * Deletes every EventSub subscription Twitch holds for a broadcaster.
 *
 * Called when a user removes the bot. Without this, Twitch keeps delivering
 * stream.online/offline, chat and ad-break webhooks for a channel that has
 * uninstalled — "phantom subscriptions" that consume the app's subscription
 * quota indefinitely and leave the bot's allowlist as the only thing standing
 * between a removed channel and the bot acting in it.
 *
 * Teardown must not depend on the bot service being warm, so it runs here
 * rather than relying on the bot's Firestore listener.
 *
 * @param channelLogin - Channel login name (for logging)
 * @param broadcasterUserId - Twitch user ID of the broadcaster
 * @returns Counts of deleted and failed subscription deletions
 */
export async function deleteAllSubscriptionsForUser(
  channelLogin: string,
  broadcasterUserId: string,
): Promise<{ deleted: number; failed: number }> {
  const appAccessToken = await getAppAccessToken();

  const headers = {
    Authorization: `Bearer ${appAccessToken}`,
    "Client-ID": TWITCH_CLIENT_ID,
    "Content-Type": "application/json",
  };

  // Collect every subscription for this broadcaster. Twitch paginates this
  // endpoint, so follow the cursor — a partial page would silently leave
  // subscriptions behind, which is the exact failure this function prevents.
  const subscriptions: { id: string; type: string }[] = [];
  let cursor: string | undefined;

  do {
    const list = await axios.get(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, {
      headers,
      params: {
        user_id: String(broadcasterUserId),
        ...(cursor ? { after: cursor } : {}),
      },
    });

    subscriptions.push(...(list.data?.data || []));
    cursor = list.data?.pagination?.cursor;
  } while (cursor);

  let deleted = 0;
  let failed = 0;

  // Delete each individually so one failure cannot abandon the rest.
  for (const sub of subscriptions) {
    try {
      await axios.delete(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, {
        headers,
        params: { id: sub.id },
      });

      deleted++;
      logger.info("Deleted EventSub subscription", {
        channelLogin,
        subscriptionId: sub.id,
        type: sub.type,
      });
    } catch (error: unknown) {
      const err = error as { response?: { status?: number; data?: unknown }; message: string };

      // A 404 means it is already gone, which is the outcome we wanted.
      if (err.response?.status === 404) {
        deleted++;
        continue;
      }

      failed++;
      logger.error("Failed to delete EventSub subscription", {
        channelLogin,
        subscriptionId: sub.id,
        type: sub.type,
        message: err.message,
        status: err.response?.status,
        twitchError: err.response?.data,
      });
    }
  }

  logger.info("EventSub teardown complete", {
    channelLogin,
    broadcasterUserId,
    found: subscriptions.length,
    deleted,
    failed,
  });

  return { deleted, failed };
}

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

    // Get user ID from Firestore — need to query by channelName since we only have login
    const channelsSnapshot = await db.collection(CHANNELS_COLLECTION)
      .where("channelName", "==", channelLogin).limit(1).get();
    const userDoc = channelsSnapshot.empty ? null : channelsSnapshot.docs[0];
    const userId = userDoc?.data()?.twitchUserId || userDoc?.id;

    if (!userId) {
      logger.warn("No user ID found for channel", { channelLogin });
      return;
    }

    // Verify user has granted channel:read:ads scope
    try {
      const userToken = await getValidTwitchTokenForUser(userId);
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
