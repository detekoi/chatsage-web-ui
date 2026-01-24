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
 * Update auto-chat configuration (partial updates supported)
 */
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const db = getDb();

  try {
    const body = req.body || {};
    const inputCategories = body.categories && typeof body.categories === "object" ? body.categories : {};

    // Fetch existing config first to merge with
    const docRef = db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin);
    const existingSnap = await docRef.get();
    const existingData = existingSnap.exists ? existingSnap.data() : {};
    const existingCategories = existingData?.categories || {};

    // Start with existing categories, then override only what was sent
    const mergedCategories: Record<string, boolean> = {
      greetings: existingCategories.greetings !== false,
      facts: existingCategories.facts !== false,
      questions: existingCategories.questions !== false,
      celebrations: existingCategories.celebrations !== false,
      ads: existingCategories.ads === true,
    };

    // Override only the categories that were explicitly sent
    if (typeof inputCategories.greetings === "boolean") {
      mergedCategories.greetings = inputCategories.greetings;
    }
    if (typeof inputCategories.facts === "boolean") {
      mergedCategories.facts = inputCategories.facts;
    }
    if (typeof inputCategories.questions === "boolean") {
      mergedCategories.questions = inputCategories.questions;
    }
    if (typeof inputCategories.celebrations === "boolean") {
      mergedCategories.celebrations = inputCategories.celebrations;
    }
    if (typeof inputCategories.ads === "boolean") {
      mergedCategories.ads = inputCategories.ads;
    }

    // Determine mode: use provided value, or keep existing, or default to "off"
    let mode = existingData?.mode || "off";
    if (typeof body.mode === "string" && body.mode.trim() !== "") {
      try {
        mode = validateMode(body.mode.toLowerCase(), AUTO_CHAT_MODES);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: (error as Error).message,
        });
      }
    }

    const updates = {
      channelName: channelLogin,
      updatedAt: new Date(),
      mode,
      categories: mergedCategories,
    };

    await docRef.set(updates, { merge: true });

    logger.info("Auto-chat config updated", {
      channelLogin,
      mode: updates.mode,
      categories: updates.categories,
    });

    // Handle EventSub subscription for ads if ads setting was changed
    if (typeof inputCategories.ads === "boolean") {
      try {
        await ensureAdBreakSubscription(channelLogin, inputCategories.ads);
      } catch (subErr) {
        logger.warn("EventSub subscription warning", {
          channelLogin,
          error: (subErr as Error).message,
        });
        // Don't fail the request if EventSub setup fails
      }
    }

    res.json({
      success: true,
      config: {
        mode: updates.mode,
        categories: updates.categories,
      },
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
