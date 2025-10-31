/**
 * Internal EventSub router
 * Endpoints for bot to manage EventSub subscriptions
 */

import { Router, Request, Response } from "express";
import { logger } from "@/config/logger";
import { ensureAdBreakSubscription } from "@/twitch";

const router = Router();

/**
 * POST /internal/eventsub/adbreak/ensure
 * Ensure ad break EventSub subscription exists or is removed
 */
router.post("/adbreak/ensure", async (req: Request, res: Response) => {
  try {
    const { channelLogin, adsEnabled } = req.body;

    if (!channelLogin) {
      return res.status(400).json({
        success: false,
        message: "Missing channelLogin",
      });
    }

    logger.info("Managing ad break subscription", {
      channelLogin,
      adsEnabled: adsEnabled === true,
    });

    await ensureAdBreakSubscription(channelLogin, adsEnabled === true);

    res.json({
      success: true,
      message: `EventSub ad-break subscription updated for ${channelLogin}`,
    });
  } catch (error) {
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
