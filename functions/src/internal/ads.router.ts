/**
 * Internal ads router
 * Endpoints for bot to fetch ad schedule information
 */

import { Router, Request, Response } from "express";
import axios from "axios";
import { getDb } from "@/config/database";
import { TWITCH_CLIENT_ID, CHANNELS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { getValidTwitchTokenForUser } from "@/tokens";
import { sanitizeChannelLogin } from "@/utils/validation";

const router = Router();

/**
 * GET /internal/ads/schedule?channel=<channelLogin>
 * Get ad schedule for a channel (bot internal use only)
 */
router.get("/schedule", async (req: Request, res: Response) => {
  try {
    const channelLoginRaw = req.query.channel;

    if (!channelLoginRaw) {
      logger.error("Missing channel parameter");
      return res.status(400).json({
        success: false,
        message: "Missing channel parameter",
      });
    }

    // Sanitize and validate channel login
    let channelLogin: string;
    try {
      channelLogin = sanitizeChannelLogin(channelLoginRaw);
    } catch (error) {
      logger.error("Invalid channel parameter", {
        error: (error as Error).message,
      });
      return res.status(400).json({
        success: false,
        message: "Invalid channel parameter",
      });
    }

    logger.info("Fetching ad schedule", { channelLogin });

    const db = getDb();

    // Find user by channel name and get valid access token
    const channelsSnapshot = await db.collection(CHANNELS_COLLECTION)
      .where("channelName", "==", channelLogin).limit(1).get();

    if (channelsSnapshot.empty) {
      logger.error("Channel not found in Firestore", { channelLogin });
      return res.status(404).json({
        success: false,
        message: "User not found or missing Twitch user ID",
      });
    }

    const userId = channelsSnapshot.docs[0].id;
    const accessToken = await getValidTwitchTokenForUser(userId);

    logger.debug("Calling Twitch API for ad schedule", {
      channelLogin,
      broadcasterId: userId,
    });

    // Call Twitch API
    const response = await axios.get("https://api.twitch.tv/helix/channels/ads", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Client-ID": TWITCH_CLIENT_ID,
      },
      params: { broadcaster_id: String(userId) },
      timeout: 15000,
    });

    logger.info("Twitch API response received", {
      channelLogin,
      hasData: !!response.data,
    });

    res.json({
      success: true,
      data: response.data,
    });
  } catch (error) {
    const err = error as {
      response?: {
        status?: number;
        data?: unknown;
      };
      message: string;
      stack?: string;
    };

    const channelLogin = (req.query?.channel || "unknown").toString().toLowerCase();

    logger.error("Error fetching ad schedule", {
      channelLogin,
      message: err.message,
      twitchApiError: err.response?.data,
      status: err.response?.status,
      stack: err.stack,
    });

    const statusCode = err.response?.status || 500;
    res.status(statusCode).json({
      success: false,
      message: err.message,
      details: err.response?.data,
    });
  }
});

export default router;
