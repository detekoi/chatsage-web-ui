/**
 * Auth status router
 * Endpoints for checking and refreshing authentication status
 */

import { Router, Response } from "express";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { getValidTwitchTokenForUser, clearUserTokens } from "@/tokens";
import { needsReAuth } from "@/utils/errors";

const router = Router();

/**
 * GET /api/auth/status
 * Check authentication status for the current user
 */
router.get("/status", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const userLogin = req.user.login;

  logger.info("Checking auth status", { userLogin });

  try {
    await getValidTwitchTokenForUser(userLogin);

    res.json({
      success: true,
      isAuthenticated: true,
      needsReAuth: false,
      message: "Twitch authentication is valid",
    });
  } catch (error) {
    logger.error("Error getting valid token", {
      userLogin,
      error: (error as Error).message,
    });

    const requiresReAuth = needsReAuth(error);

    res.status(403).json({
      success: false,
      isAuthenticated: true,
      needsReAuth: requiresReAuth,
      message: requiresReAuth
        ? "Twitch authentication required. Please re-authenticate with Twitch."
        : "Error validating Twitch authentication.",
    });
  }
});

/**
 * POST /api/auth/refresh
 * Force a token refresh for the current user
 */
router.post("/refresh", async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const userLogin = req.user.login;

  logger.info("Forcing token refresh", { userLogin });

  try {
    // Clear cached tokens first
    await clearUserTokens(userLogin, "Manual refresh requested by user");

    // Get a fresh token (this will trigger refresh)
    const accessToken = await getValidTwitchTokenForUser(userLogin);

    if (!accessToken) {
      throw new Error("Failed to obtain access token after refresh");
    }

    logger.info("Successfully refreshed token", { userLogin });

    res.json({
      success: true,
      message: "Twitch authentication successfully refreshed",
    });
  } catch (error) {
    logger.error("Error refreshing token", {
      userLogin,
      error: (error as Error).message,
    });

    const requiresReAuth = needsReAuth(error);

    res.status(403).json({
      success: false,
      needsReAuth: requiresReAuth,
      message: requiresReAuth
        ? "Twitch re-authentication required. Please log in with Twitch again."
        : "Error refreshing Twitch authentication.",
    });
  }
});

export default router;
