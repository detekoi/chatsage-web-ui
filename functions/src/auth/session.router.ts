/**
 * Session router
 * Handles logout and session management
 */

import { Router, Request, Response } from "express";
import { FRONTEND_URL_CONFIG } from "@/config/constants";
import { logger } from "@/config/logger";

const router = Router();

/**
 * GET /logout
 * Clears session cookie and redirects to frontend
 */
router.get("/logout", (req: Request, res: Response) => {
  logger.info("User logging out (GET)");

  res.clearCookie("session_token", { path: "/" });
  res.redirect(FRONTEND_URL_CONFIG);
});

/**
 * POST /api/logout
 * Clears session cookie and returns JSON response
 */
router.post("/api/logout", (req: Request, res: Response) => {
  logger.info("User logging out (POST)");

  res.clearCookie("session_token", { path: "/" });
  res.json({
    success: true,
    message: "Logged out successfully",
  });
});

export default router;
