/**
 * Express middleware configuration
 * CORS, security headers, and rate limiting
 */

import express, { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import {
  ALLOWED_ORIGINS,
  RATE_LIMIT,
  IS_PRODUCTION,
  REQUEST_TIMEOUT_MS,
} from "./constants";
import { requestIdMiddleware } from "./logger";

/**
 * CORS and security headers middleware
 */
export function corsAndSecurityMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const origin = req.headers.origin;

  // Set CORS headers
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS",
  );
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

  // Content Security Policy
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' https://app.rybbit.io; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "img-src 'self' data: https:; " +
      "connect-src 'self' https://api.wildcat.chat https://api.twitch.tv; " +
      "frame-ancestors 'none';",
  );

  // Strict-Transport-Security (HSTS) for production
  if (IS_PRODUCTION) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains; preload",
    );
  }

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    res.sendStatus(204);
    return;
  }

  next();
}

/**
 * Rate limiter for authentication endpoints
 */
export const authLimiter = rateLimit({
  windowMs: RATE_LIMIT.AUTH.windowMs,
  max: RATE_LIMIT.AUTH.max,
  message: "Too many authentication attempts, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for API endpoints
 */
export const apiLimiter = rateLimit({
  windowMs: RATE_LIMIT.API.windowMs,
  max: RATE_LIMIT.API.max,
  message: "Too many requests, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Request timeout middleware
 */
export function requestTimeoutMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const timeout = setTimeout(() => {
    if (!res.headersSent) {
      res.status(408).json({
        success: false,
        message: "Request timeout",
      });
    }
  }, REQUEST_TIMEOUT_MS);

  res.on("finish", () => clearTimeout(timeout));
  res.on("close", () => clearTimeout(timeout));

  next();
}

/**
 * Setup all common middleware for Express app
 */
export function setupMiddleware(app: express.Application) {
  // Trust proxy headers from Cloud Run/Firebase Hosting
  app.set("trust proxy", true);

  // Body parsing and cookies
  app.use(express.json());
  app.use(cookieParser());

  // Request tracking
  app.use(requestIdMiddleware);

  // Request timeout
  app.use(requestTimeoutMiddleware);

  // CORS and security headers
  app.use(corsAndSecurityMiddleware);
}

/**
 * Middleware to ensure Firestore is initialized
 */
export async function requireFirestore(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    // Dynamic import to avoid circular dependency
    const { getDb } = await import("./database");
    getDb(); // Will throw if not initialized
    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Database not available",
    });
  }
}
