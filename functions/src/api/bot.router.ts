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
import { getAllowedChannelsList } from "@/utils/secrets";
import { getUserIdFromUsername, addModerator } from "@/twitch";

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
      await getValidTwitchTokenForUser(channelLogin);
    } catch (tokenError) {
      logger.warn("Token validation failed in status check", {
        channelLogin,
        error: (tokenError as Error).message,
      });
    }

    const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
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
      message: "Error fetching bot status",
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
    // Check if channel is on allow-list
    const allowedList = await getAllowedChannelsList();
    const isAllowed = allowedList.includes(channelLogin.toLowerCase());

    if (!isAllowed) {
      logger.warn("Channel not on allow-list", { channelLogin });
      return res.status(403).json({
        success: false,
        message: "Your channel is not on the allow-list. Contact support for access.",
      });
    }

    // Verify valid Twitch token
    try {
      await getValidTwitchTokenForUser(channelLogin);
      logger.info("Verified valid Twitch token", { channelLogin });
    } catch (tokenError) {
      logger.error("Token validation failed", {
        channelLogin,
        error: (tokenError as Error).message,
      });
      return res.status(403).json({
        success: false,
        message: "Twitch authentication required. Please re-authenticate with Twitch.",
      });
    }

    // Activate the bot for this channel
    const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
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
      message: `Bot successfully added to ${channelLogin}.`,
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
      message: "Failed to add bot. Please try again.",
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
      await getValidTwitchTokenForUser(channelLogin);
      logger.info("Verified valid Twitch token", { channelLogin });
    } catch (tokenError) {
      logger.warn("Token validation failed, but allowing removal", {
        channelLogin,
        error: (tokenError as Error).message,
      });
    }

    const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
    const docSnap = await docRef.get();

    if (docSnap.exists) {
      await docRef.update({
        isActive: false,
        removedAt: FieldValue.serverTimestamp(),
      });

      logger.info("Channel deactivated successfully", { channelLogin });
      res.json({
        success: true,
        message: `Bot successfully removed from ${channelLogin}.`,
      });
    } else {
      logger.warn("No document found for channel", { channelLogin });
      res.json({
        success: true,
        message: `No active bot found for ${channelLogin}.`,
      });
    }
  } catch (error) {
    logger.error("Error removing bot from channel", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to remove bot. Please try again.",
    });
  }
});

export default router;
