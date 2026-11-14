/**
 * Response style router
 * Endpoints for the De-Slop switch, which makes the bot's AI-written text plainer.
 * Documents: channelResponseStyles/{broadcasterId}, keyed by broadcaster ID, not
 * login (see utils/channelKey). `channelName` is stored for readability only.
 *
 * The bot reads these documents with a listener (src/components/context/
 * responseStyleStorage.js in twitch-knowledge-bot) and writes the same field
 * from the !deslop chat command.
 */

import { Router, Response } from "express";
import { getDb } from "@/config/database";
import { RESPONSE_STYLE_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { channelDocKey } from "@/utils/channelKey";
import { tr } from "@/i18n";

const router = Router();

/**
 * GET /api/response-style
 * Returns the De-Slop setting for the authenticated user's channel. Off when
 * nothing is stored, and for a stored value that is not a boolean.
 */
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  try {
    const snap = await getDb().collection(RESPONSE_STYLE_COLLECTION).doc(channelDocKey(req.user)).get();
    res.json({ success: true, deslop: snap.exists && snap.data()?.deslop === true });
  } catch (error) {
    logger.error("Error fetching response style", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.responseStyle.FailedLoad", {}, "The De-Slop setting did not load. Try again."),
    });
  }
});

/**
 * POST /api/response-style
 * Body: { deslop: boolean }
 */
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const deslop = req.body?.deslop;

  if (typeof deslop !== "boolean") {
    return res.status(400).json({
      success: false,
      message: tr(req, "api.responseStyle.InvalidDeslop", {}, "deslop must be true or false."),
    });
  }

  try {
    await getDb().collection(RESPONSE_STYLE_COLLECTION).doc(channelDocKey(req.user)).set(
      { channelName: channelLogin, updatedAt: new Date(), deslop },
      { merge: true },
    );
    logger.info("Response style updated", { channelLogin, deslop });
    res.json({ success: true, deslop });
  } catch (error) {
    logger.error("Error saving response style", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.responseStyle.FailedSave", {}, "The De-Slop setting did not save. Try again."),
    });
  }
});

export default router;
