/**
 * Internal authentication middleware
 * Authenticates requests from the bot service using internal token
 */

import { Request, Response, NextFunction } from "express";
import * as crypto from "crypto";
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

    // Compare fixed-length digests rather than the raw tokens. A raw comparison
    // needs a length guard, and a guard on String.length (UTF-16 code units)
    // does not imply equal Buffer byte length — "é" and "a" are both length 1
    // but 2 and 1 bytes — so timingSafeEqual would still throw a RangeError.
    // Hashing makes both operands 32 bytes, so the comparison cannot throw and
    // does not leak the token's length.
    const tokenDigest = crypto.createHash("sha256").update(token, "utf8").digest();
    const expectedDigest = crypto.createHash("sha256").update(expected, "utf8").digest();

    if (!crypto.timingSafeEqual(tokenDigest, expectedDigest)) {
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
