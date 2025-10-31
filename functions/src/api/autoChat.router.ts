/**
 * Auto-chat router
 * Endpoints for managing auto-chat configuration
 */

import { Router, Response } from "express";
import { getDb } from "@/config/database";
import { AUTO_CHAT_COLLECTION, AUTO_CHAT_MODES, DEFAULT_AUTO_CHAT_CONFIG } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { validateMode } from "@/utils/validation";
import { ensureAdBreakSubscription } from "@/twitch";

const router = Router();

/**
 * GET /api/auto-chat
 * Get auto-chat configuration for the authenticated user's channel
 */
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const db = getDb();

  try {
    const docRef = db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin);
    const snap = await docRef.get();

    const defaultCfg = DEFAULT_AUTO_CHAT_CONFIG;
    const cfg = snap.exists ? { ...defaultCfg, ...snap.data() } : defaultCfg;

    res.json({
      success: true,
      config: {
        mode: cfg.mode || "off",
        categories: {
          greetings: cfg.categories?.greetings !== false,
          facts: cfg.categories?.facts !== false,
          questions: cfg.categories?.questions !== false,
          celebrations: cfg.categories?.celebrations !== false,
          ads: cfg.categories?.ads === true,
        },
      },
    });
  } catch (error) {
    logger.error("Error fetching auto-chat config", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to load auto-chat config",
    });
  }
});

/**
 * POST /api/auto-chat
 * Update auto-chat configuration
 */
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const db = getDb();

  try {
    const body = req.body || {};
    const modeInput = (body.mode || "").toLowerCase();

    // Validate mode
    let mode = "off";
    try {
      mode = validateMode(modeInput || "off", AUTO_CHAT_MODES);
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: (error as Error).message,
      });
    }

    const categories = body.categories && typeof body.categories === "object" ? body.categories : {};

    const updates = {
      mode,
      categories: {
        greetings: categories.greetings !== false,
        facts: categories.facts !== false,
        questions: categories.questions !== false,
        celebrations: categories.celebrations !== false,
        ads: categories.ads === true,
      },
      channelName: channelLogin,
      updatedAt: new Date(),
    };

    await db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin).set(updates, { merge: true });

    logger.info("Auto-chat config updated", {
      channelLogin,
      mode: updates.mode,
      adsEnabled: updates.categories.ads,
    });

    // Handle EventSub subscription for ads
    try {
      if (typeof updates.categories.ads === "boolean") {
        await ensureAdBreakSubscription(channelLogin, updates.categories.ads);
      }
    } catch (subErr) {
      logger.warn("EventSub subscription warning", {
        channelLogin,
        error: (subErr as Error).message,
      });
      // Don't fail the request if EventSub setup fails
    }

    res.json({
      success: true,
      config: updates,
    });
  } catch (error) {
    logger.error("Error saving auto-chat config", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Failed to save auto-chat config",
    });
  }
});

export default router;
