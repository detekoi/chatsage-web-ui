/**
 * Main entry point for Firebase Cloud Functions
 * Wires together all routers and middleware
 */

import * as functions from "firebase-functions";
import express from "express";
import { initializeDatabase } from "@/config/database";
import { setupMiddleware, authLimiter } from "@/config/middleware";
import { logger } from "@/config/logger";
import { oauthRouter, sessionRouter } from "@/auth";
import apiRouter from "@/api";
import internalRouter from "@/internal";

// Initialize database connections
try {
  initializeDatabase();
} catch (error) {
  logger.error("Failed to initialize database", {
    error: (error as Error).message,
  });
}

// Create Express app
const app = express();

// Setup common middleware (CORS, security headers, etc.)
setupMiddleware(app);

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    name: "ChatSage Web UI",
    version: "2.0.0",
    status: "running",
    message: "TypeScript refactored version with enhanced security",
  });
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Test environment variables endpoint (for debugging)
app.get("/test/env", (req, res) => {
  const {
    TWITCH_CLIENT_ID,
    TWITCH_CLIENT_SECRET,
    CALLBACK_REDIRECT_URI_CONFIG,
    FRONTEND_URL_CONFIG,
    JWT_SECRET,
    WEBUI_INTERNAL_TOKEN,
    ALLOWED_CHANNELS_SECRET_NAME,
    BOT_PUBLIC_URL,
    TWITCH_EVENTSUB_SECRET,
  } = process.env;

  res.json({
    twitchClientId: TWITCH_CLIENT_ID ? "Set" : "Not Set",
    twitchClientSecret: TWITCH_CLIENT_SECRET ? "Set" : "Not Set",
    callbackRedirectUri: CALLBACK_REDIRECT_URI_CONFIG || "Not Set",
    frontendUrl: FRONTEND_URL_CONFIG || "Not Set",
    jwtSecret: JWT_SECRET ? "Set" : "Not Set",
    webuiInternalToken: WEBUI_INTERNAL_TOKEN ? "Set" : "Not Set",
    allowedChannelsSecretName: ALLOWED_CHANNELS_SECRET_NAME || "Not Set",
    botPublicUrl: BOT_PUBLIC_URL || "Not Set",
    twitchEventsubSecret: TWITCH_EVENTSUB_SECRET ? "Set" : "Not Set",
  });
});

// Mount auth routes (with rate limiting)
app.use("/auth", authLimiter, oauthRouter);
app.use("/", sessionRouter); // Logout routes at root

// Mount API routes (authenticated endpoints)
app.use("/api", apiRouter);

// Mount internal routes (bot service endpoints)
app.use("/internal", internalRouter);

// 404 handler
app.use((req, res) => {
  logger.warn("404 - Route not found", {
    method: req.method,
    path: req.path,
  });
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// Error handler
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error("Unhandled error", {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === "production"
      ? "Internal server error"
      : err.message,
  });
});

// Export as Firebase Cloud Function
export const webUi = functions.https.onRequest(app);

logger.info("Cloud Function initialized successfully");
