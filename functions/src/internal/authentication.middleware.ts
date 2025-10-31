/**
 * Internal authentication middleware
 * Authenticates requests from the bot service using internal token
 */

import { Request, Response, NextFunction } from "express";
import { logger } from "@/config/logger";
import { getInternalBotTokenValue } from "@/utils/secrets";

/**
 * Middleware to authenticate internal bot requests
 * Verifies the Bearer token matches the internal bot token
 */
export async function authenticateInternalRequest(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";

  if (!token) {
    logger.warn("Missing internal authorization token", {
      path: req.path,
    });
    res.status(401).json({
      success: false,
      message: "Unauthorized: Missing token",
    });
    return;
  }

  try {
    const expected = await getInternalBotTokenValue();

    if (token !== expected) {
      logger.warn("Invalid internal authorization token", {
        path: req.path,
      });
      res.status(401).json({
        success: false,
        message: "Unauthorized: Invalid token",
      });
      return;
    }

    logger.debug("Internal request authenticated", {
      path: req.path,
    });

    next();
  } catch (error) {
    logger.error("Error validating internal token", {
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}
