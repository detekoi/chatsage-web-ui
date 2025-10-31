/**
 * JWT authentication middleware
 * Verifies and decodes JWT tokens for API requests
 */

import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { JWT_SECRET } from "@/config/constants";
import { sanitizeUsername } from "@/utils/validation";
import { logger } from "@/config/logger";

/**
 * Extended request type with authenticated user
 */
export interface AuthenticatedRequest extends Request {
  user: {
    login: string;
    userId: string;
    displayName: string;
    email: string | null;
  };
}

/**
 * JWT payload structure
 */
interface JwtPayload {
  login: string;
  userId: string;
  displayName: string;
  email?: string | null;
}

/**
 * Middleware to authenticate API requests using JWT
 * Verifies the Bearer token in Authorization header
 */
export function authenticateApiRequest(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    logger.warn("Missing authorization token", {
      path: req.path,
      method: req.method,
    });
    res.status(401).json({
      success: false,
      message: "Unauthorized: Missing token",
    });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;

    // Validate required fields
    if (!decoded.login || !decoded.userId) {
      throw new Error("Invalid token payload: missing required fields");
    }

    // Attach user to request
    (req as AuthenticatedRequest).user = {
      login: sanitizeUsername(decoded.login),
      userId: decoded.userId,
      displayName: decoded.displayName,
      email: decoded.email || null,
    };

    logger.debug("User authenticated via JWT", {
      login: (req as AuthenticatedRequest).user.login,
      userId: (req as AuthenticatedRequest).user.userId,
    });

    next();
  } catch (err: any) {
    logger.error("JWT verification failed", {
      error: err.message,
      path: req.path,
    });

    res.status(401).json({
      success: false,
      message: "Unauthorized: Invalid token",
    });
    return;
  }
}

/**
 * Creates a JWT session token for a user
 * @param user - User information
 * @param expiresIn - Token expiration (default: 7 days)
 * @returns Signed JWT token
 */
export function createSessionToken(
  user: {
    login: string;
    userId: string;
    displayName: string;
    email?: string | null;
  },
  expiresIn = "7d",
): string {
  const payload: JwtPayload = {
    login: user.login,
    userId: user.userId,
    displayName: user.displayName,
    email: user.email || null,
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn } as jwt.SignOptions);
}
