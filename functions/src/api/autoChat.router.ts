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
    const categories = body.categories && typeof body.categories === "object" ? body.categories : {};

    // Build updates object with only fields that were explicitly sent
    // Use dot notation for category fields to avoid overwriting unrelated settings
    const updates: Record<string, unknown> = {
      channelName: channelLogin,
      updatedAt: new Date(),
    };

    // Only update mode if explicitly provided
    if (typeof body.mode === "string" && body.mode.trim() !== "") {
      try {
        updates.mode = validateMode(body.mode.toLowerCase(), AUTO_CHAT_MODES);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: (error as Error).message,
        });
      }
    }

    // Only update category fields that were explicitly sent
    // Using dot notation preserves other category fields
    if (typeof categories.greetings === "boolean") {
      updates["categories.greetings"] = categories.greetings;
    }
    if (typeof categories.facts === "boolean") {
      updates["categories.facts"] = categories.facts;
    }
    if (typeof categories.questions === "boolean") {
      updates["categories.questions"] = categories.questions;
    }
    if (typeof categories.celebrations === "boolean") {
      updates["categories.celebrations"] = categories.celebrations;
    }
    if (typeof categories.ads === "boolean") {
      updates["categories.ads"] = categories.ads;
    }

    await db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin).set(updates, { merge: true });

    logger.info("Auto-chat config updated", {
      channelLogin,
      updatedFields: Object.keys(updates).filter(k => k !== "channelName" && k !== "updatedAt"),
    });

    // Handle EventSub subscription for ads if ads setting was changed
    if (typeof categories.ads === "boolean") {
      try {
        await ensureAdBreakSubscription(channelLogin, categories.ads);
      } catch (subErr) {
        logger.warn("EventSub subscription warning", {
          channelLogin,
          error: (subErr as Error).message,
        });
        // Don't fail the request if EventSub setup fails
      }
    }

    // Fetch and return the full current config
    const docRef = db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin);
    const snap = await docRef.get();
    const cfg = snap.exists ? snap.data() : {};

    res.json({
      success: true,
      config: {
        mode: cfg?.mode || "off",
        categories: {
          greetings: cfg?.categories?.greetings !== false,
          facts: cfg?.categories?.facts !== false,
          questions: cfg?.categories?.questions !== false,
          celebrations: cfg?.categories?.celebrations !== false,
          ads: cfg?.categories?.ads === true,
        },
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
