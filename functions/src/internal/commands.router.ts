/**
 * Internal commands router
 * Endpoints for bot to save command settings
 */

import { Router, Request, Response } from "express";
import { getDb, FieldValue } from "@/config/database";
import { CHANNEL_COMMANDS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";

const router = Router();

/**
 * POST /internal/commands/save
 * Save command settings from bot
 */
router.post("/save", async (req: Request, res: Response) => {
  try {
    const { channelLogin, commandSettings } = req.body;

    if (!channelLogin || typeof commandSettings !== "object") {
      return res.status(400).json({
        success: false,
        message: "Invalid request body",
      });
    }

    const db = getDb();
    const docRef = db.collection(CHANNEL_COMMANDS_COLLECTION).doc(channelLogin);

    const updates: Record<string, unknown> = {};
    for (const cmd of Object.keys(commandSettings)) {
      updates[cmd] = commandSettings[cmd];
    }
    updates.lastUpdatedAt = FieldValue.serverTimestamp();

    await docRef.set(updates, { merge: true });

    logger.info("Saved command settings", {
      channelLogin,
      commandCount: Object.keys(commandSettings).length,
    });

    res.json({
      success: true,
      message: "Command settings saved successfully",
    });
  } catch (error) {
    logger.error("Error saving command settings", {
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error saving command settings",
    });
  }
});

export default router;
