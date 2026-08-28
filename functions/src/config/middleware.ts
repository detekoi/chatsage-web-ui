/**
 * Express middleware configuration
 * CORS, security headers, and rate limiting
 */

import express, { Request, Response, NextFunction } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import {
  ALLOWED_ORIGINS,
  RATE_LIMIT,
  IS_PRODUCTION,
  REQUEST_TIMEOUT_MS,
} from "./constants";
import { requestIdMiddleware } from "./logger";

/*
 * There is deliberately no CSRF middleware here.
 *
 * CSRF defends credentials the browser attaches on its own. Every
 * authenticated route on this service reads `Authorization: Bearer`, which is
 * set by our own JavaScript and which another origin cannot make the browser
 * send. The one cookie in the app — the `__session` OAuth state cookie — is
 * only ever read on a top-level GET, where the state binding is the control.
 *
 * A double-submit implementation did live here. It protected nothing: its
 * token was never issued to any client, the frontend never sent one, every
 * non-GET route was on the skip list, and Firebase Hosting strips every cookie
 * except `__session` before a request reaches this function, so its cookie
 * never arrived either.
 *
 * Bring it back — with an endpoint that actually issues tokens — if the session
 * ever moves from `Authorization` into a cookie. That change, and only that
 * change, is what would make this necessary.
 */

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
  res.setHeader(
    "Access-Control-Allow-Headers",
    // X-Locale carries the dashboard's active language so responses can be localized.
    // Without it here, the preflight rejects the header on any cross-origin call.
    "Content-Type, Authorization, X-Locale",
  );

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
 * Builds a rate limiter for writes that trigger an LLM safety check.
 *
 * Applied on top of apiLimiter. Keyed by authenticated user rather than IP: the
 * cost being limited is per-account LLM spend, and several broadcasters can
 * share an IP.
 *
 * `willScreen` decides which requests count against the budget. It must be
 * conservative — returning true when unsure — since the cost of over-counting is
 * a slower save, and the cost of under-counting is unmetered LLM spend.
 *
 * @param willScreen - True when this request may run a safety check.
 */
function createPromptWriteLimiter(willScreen: (req: Request) => boolean) {
  return rateLimit({
    windowMs: RATE_LIMIT.PROMPT_WRITE.windowMs,
    max: RATE_LIMIT.PROMPT_WRITE.max,
    message: "Too many personality or prompt saves. Please wait a moment and try again.",
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req: Request) => !willScreen(req),
    keyGenerator: (req: Request) =>
      (req as Request & { user?: { userId?: string } }).user?.userId ||
      ipKeyGenerator(req.ip || ""),
  });
}

/** Every persona POST screens; GET and DELETE never do. */
export const personaWriteLimiter = createPromptWriteLimiter(
  (req) => req.method === "POST",
);

/**
 * Custom commands and timers only screen prompt-typed text, so plain "text"
 * commands and metadata-only edits must not consume the budget — a streamer
 * adding a batch of ordinary commands should never hit this.
 *
 * POST is fully determinable: type defaults to "text", so only an explicit
 * "prompt" screens. PUT cannot see the stored type, so it counts any request
 * that changes the text or sets the type, and skips pure metadata edits.
 */
export const aiPromptWriteLimiter = createPromptWriteLimiter((req) => {
  if (req.method !== "POST" && req.method !== "PUT") return false;
  const body = (req.body || {}) as { type?: unknown; response?: unknown };
  if (req.method === "POST") return body.type === "prompt";
  return body.type === "prompt" || body.response !== undefined;
});

/** Check-in only screens when AI mode is on and a prompt was supplied. */
export const checkinWriteLimiter = createPromptWriteLimiter((req) => {
  const body = (req.body || {}) as { useAi?: unknown; aiPrompt?: unknown };
  return Boolean(body.useAi) && typeof body.aiPrompt === "string" && body.aiPrompt.trim() !== "";
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

  // CORS and security headers (must be first so error responses include CORS headers)
  app.use(corsAndSecurityMiddleware);

  // Body parsing. No cookie parser: the only cookie this service reads is the
  // OAuth state cookie, and auth/state.ts reads it straight off the header so
  // state binding does not depend on middleware order.
  app.use(express.json());

  // Request tracking
  app.use(requestIdMiddleware);

  // Request timeout
  app.use(requestTimeoutMiddleware);
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
  } catch {
    res.status(500).json({
      success: false,
      message: "Database not available",
    });
  }
}
