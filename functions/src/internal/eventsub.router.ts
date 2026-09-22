/**
 * Internal EventSub router
 * Endpoints for bot to manage EventSub subscriptions
 */

import { Router, Request, Response } from "express";
import { getDb } from "@/config/database";
import { CHANNELS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { AdBreakPrerequisiteError, ensureAdBreakSubscription } from "@/twitch";

const router = Router();

/**
 * Resolves the broadcaster ID for a request. The bot sends `twitchUserId`; the
 * login-only form is kept so a bot that predates that field keeps working, at
 * the cost of the lookup missing a channel that has renamed since it logged in.
 */
async function resolveBroadcasterId(body: { twitchUserId?: unknown; channelLogin?: unknown }): Promise<string | null> {
  const id = body.twitchUserId == null ? "" : String(body.twitchUserId).trim();
  if (/^\d+$/.test(id)) return id;

  const login = typeof body.channelLogin === "string" ? body.channelLogin.trim().toLowerCase() : "";
  if (!login) return null;
  const snapshot = await getDb().collection(CHANNELS_COLLECTION)
    .where("channelName", "==", login).limit(1).get();
  if (snapshot.empty) return null;
  const doc = snapshot.docs[0];
  return String(doc.data()?.twitchUserId || doc.id);
}

/**
 * POST /internal/eventsub/adbreak/ensure
 * Ensure ad break EventSub subscription exists or is removed.
 * Body: { twitchUserId, channelLogin?, adsEnabled }
 */
router.post("/adbreak/ensure", async (req: Request, res: Response) => {
  try {
    const { channelLogin, adsEnabled } = req.body;
    const broadcasterId = await resolveBroadcasterId(req.body || {});

    if (!broadcasterId) {
      return res.status(400).json({
        success: false,
        message: "Missing twitchUserId (or a channelLogin that resolves to a managed channel)",
      });
    }

    logger.info("Managing ad break subscription", {
      broadcasterId,
      channelLogin,
      adsEnabled: adsEnabled === true,
    });

    await ensureAdBreakSubscription(broadcasterId, adsEnabled === true);

    res.json({
      success: true,
      message: `EventSub ad-break subscription updated for ${channelLogin || broadcasterId}`,
    });
  } catch (error) {
    // A non-2xx is what tells the bot the subscription is not in place, so it
    // keeps retrying instead of treating the channel as confirmed for hours.
    if (error instanceof AdBreakPrerequisiteError) {
      logger.warn("Ad break subscription prerequisite not met", {
        broadcasterId: error.broadcasterId,
        error: error.message,
      });
      return res.status(409).json({
        success: false,
        message: error.message,
      });
    }
    logger.error("Error managing ad break subscription", {
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: (error as Error).message,
    });
  }
});

export default router;
