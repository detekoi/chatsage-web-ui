/**
 * Bot management router
 * Endpoints for adding/removing bot and checking status
 */

import { Router, Response } from "express";
import { getDb, FieldValue } from "@/config/database";
import { CHANNELS_COLLECTION, TWITCH_BOT_USERNAME } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { getValidTwitchTokenForUser } from "@/tokens";
import { tr } from "@/i18n";
import {
  getUserIdFromUsername,
  addModerator,
  ensureStreamEventSubscriptions,
  deleteAllSubscriptionsForUser,
} from "@/twitch";

const router = Router();

/**
 * GET /api/bot/status
 * Check bot status for the authenticated user's channel
 */
router.get("/status", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const db = getDb();

  try {
    // Try to validate token (but don't fail if it doesn't work)
    try {
      await getValidTwitchTokenForUser(req.user.userId);
    } catch (tokenError) {
      logger.warn("Token validation failed in status check", {
        channelLogin,
        error: (tokenError as Error).message,
      });
    }

    const docRef = db.collection(CHANNELS_COLLECTION).doc(req.user.userId);
    const docSnap = await docRef.get();

    if (docSnap.exists && docSnap.data()?.isActive) {
      res.json({
        success: true,
        isActive: true,
        channelName: docSnap.data()?.channelName || channelLogin,
        needsReAuth: docSnap.data()?.needsTwitchReAuth === true,
      });
    } else {
      res.json({
        success: true,
        isActive: false,
        channelName: channelLogin,
        needsReAuth: docSnap.exists && docSnap.data()?.needsTwitchReAuth === true,
      });
    }
  } catch (error) {
    logger.error("Error getting bot status", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.bot.ErrorFetchingBotStatus", {}, "Error fetching bot status"),
    });
  }
});

/**
 * POST /api/bot/add
 * Add bot to the authenticated user's channel
 */
router.post("/add", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const broadcasterUserId = req.user.userId;
  const db = getDb();

  try {

    // Verify valid Twitch token
    try {
      await getValidTwitchTokenForUser(broadcasterUserId);
      logger.info("Verified valid Twitch token", { channelLogin });
    } catch (tokenError) {
      logger.error("Token validation failed", {
        channelLogin,
        error: (tokenError as Error).message,
      });
      return res.status(403).json({
        success: false,
        message: tr(req, "api.bot.TwitchAuthenticationRequiredRe", {}, "Twitch authentication required. Please re-authenticate with Twitch."),
      });
    }

    // Activate the bot for this channel
    const docRef = db.collection(CHANNELS_COLLECTION).doc(broadcasterUserId);

    // Defense-in-depth: verify doc exists (admin-created) even if JWT is valid
    const existingDoc = await docRef.get();
    if (!existingDoc.exists) {
      logger.warn("Channel not approved in Firestore", { channelLogin, broadcasterUserId });
      return res.status(403).json({
        success: false,
        message: tr(req, "api.bot.ChannelNotOnAllow", {}, "Your channel is not on the allow-list. Contact me for access: https://parfaitfair.com/#contact"),
      });
    }

    await docRef.set(
      {
        channelName: channelLogin,
        isActive: true,
        addedAt: FieldValue.serverTimestamp(),
        twitchUserId: broadcasterUserId,
      },
      { merge: true },
    );

    logger.info("Channel activated successfully", { channelLogin });

    // Create required EventSub subscriptions (stream.online, stream.offline)
    // These are CRITICAL for the bot to work with LAZY_CONNECT mode
    let eventsubStatus: { success: boolean; error?: string } = { success: false };
    try {
      logger.info("Creating EventSub subscriptions for stream events", {
        channelLogin,
        broadcasterUserId,
      });

      await ensureStreamEventSubscriptions(channelLogin, broadcasterUserId);
      eventsubStatus = { success: true };

      logger.info("EventSub subscriptions created successfully", { channelLogin });
    } catch (eventsubError) {
      logger.error("Failed to create EventSub subscriptions", {
        channelLogin,
        broadcasterUserId,
        error: (eventsubError as Error).message,
      });
      eventsubStatus = { success: false, error: (eventsubError as Error).message };
      // Don't fail the whole operation - moderator setup and IRC join can still work
    }

    // Automatically add bot as moderator
    let modStatus: { success: boolean; error?: string } = { success: false, error: "Bot username not configured" };

    if (TWITCH_BOT_USERNAME) {
      try {
        logger.info("Attempting to add bot as moderator", {
          channelLogin,
          botUsername: TWITCH_BOT_USERNAME,
        });

        const botUserId = await getUserIdFromUsername(TWITCH_BOT_USERNAME);

        if (botUserId) {
          modStatus = await addModerator(channelLogin, broadcasterUserId, botUserId);

          if (modStatus.success) {
            logger.info("Bot successfully added as moderator", { channelLogin });
          } else {
            logger.warn("Failed to add bot as moderator", {
              channelLogin,
              error: modStatus.error,
            });
          }
        } else {
          logger.warn("Could not find bot user ID", {
            botUsername: TWITCH_BOT_USERNAME,
          });
          modStatus = { success: false, error: "Bot user not found" };
        }
      } catch (modError) {
        logger.error("Error adding bot as moderator", {
          channelLogin,
          error: (modError as Error).message,
        });
        modStatus = { success: false, error: (modError as Error).message };
      }
    } else {
      logger.warn("TWITCH_BOT_USERNAME not configured, skipping moderator setup");
    }

    res.json({
      success: true,
      message: tr(req, "api.bot.BotSuccessfullyAdded", { channelLogin: channelLogin }, `Bot successfully added to ${channelLogin}.`),
      eventsubStatus: eventsubStatus.success ? "created" : "failed",
      eventsubError: eventsubStatus.success ? undefined : eventsubStatus.error,
      moderatorStatus: modStatus.success ? "added" : "failed",
      moderatorError: modStatus.success ? undefined : modStatus.error,
    });
  } catch (error) {
    logger.error("Error adding bot to channel", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.bot.FailedAddBotTry", {}, "Failed to add bot. Please try again."),
    });
  }
});

/**
 * POST /api/bot/remove
 * Remove bot from the authenticated user's channel
 */
router.post("/remove", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const db = getDb();

  try {
    // Try to validate token (but allow removal even if it fails)
    try {
      await getValidTwitchTokenForUser(req.user.userId);
      logger.info("Verified valid Twitch token", { channelLogin });
    } catch (tokenError) {
      logger.warn("Token validation failed, but allowing removal", {
        channelLogin,
        error: (tokenError as Error).message,
      });
    }

    const docRef = db.collection(CHANNELS_COLLECTION).doc(req.user.userId);
    const docSnap = await docRef.get();

    if (docSnap.exists) {
      // Deactivate first so the bot stops acting on the channel immediately,
      // even if the EventSub teardown below fails.
      await docRef.update({
        isActive: false,
        removedAt: FieldValue.serverTimestamp(),
      });

      logger.info("Channel deactivated successfully", { channelLogin });

      // Tear down EventSub subscriptions here rather than leaving it to the
      // bot's Firestore listener: the bot scales to zero, so a removal while
      // it is cold would otherwise never unsubscribe, and its startup path
      // only queries isActive == true so it never reconciles stale ones.
      const broadcasterUserId = docSnap.data()?.twitchUserId || req.user.userId;
      let eventsubTeardown: { deleted: number; failed: number } | null = null;

      try {
        eventsubTeardown = await deleteAllSubscriptionsForUser(
          channelLogin,
          String(broadcasterUserId),
        );

        if (eventsubTeardown.failed > 0) {
          await docRef.update({
            eventsubTeardownPending: true,
            eventsubTeardownFailedAt: FieldValue.serverTimestamp(),
          });
        } else {
          await docRef.update({
            eventsubTeardownPending: false,
            eventsubTeardownAt: FieldValue.serverTimestamp(),
          });
        }
      } catch (eventsubError) {
        logger.error("Failed to tear down EventSub subscriptions on removal", {
          channelLogin,
          broadcasterUserId,
          error: (eventsubError as Error).message,
        });

        // Flag for reconciliation. The channel is already deactivated, so the
        // bot's allowlist rejects any webhook that keeps arriving.
        await docRef.update({
          eventsubTeardownPending: true,
          eventsubTeardownFailedAt: FieldValue.serverTimestamp(),
        }).catch(() => undefined);
      }

      res.json({
        success: true,
        message: tr(req, "api.bot.BotSuccessfullyRemovedFrom", { channelLogin: channelLogin }, `Bot successfully removed from ${channelLogin}.`),
        eventsubTeardown,
      });
    } else {
      logger.warn("No document found for channel", { channelLogin });
      res.json({
        success: true,
        message: tr(req, "api.bot.NoActiveBotFound", { channelLogin: channelLogin }, `No active bot found for ${channelLogin}.`),
      });
    }
  } catch (error) {
    logger.error("Error removing bot from channel", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.bot.FailedRemoveBotTry", {}, "Failed to remove bot. Please try again."),
    });
  }
});

export default router;
