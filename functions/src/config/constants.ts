/**
 * Application configuration and constants
 * All environment variables and configuration values
 */

// Twitch API configuration
export const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID || "";
export const TWITCH_CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET || "";
export const TWITCH_BOT_USERNAME = process.env.TWITCH_BOT_USERNAME || "";

// OAuth URLs
export const CALLBACK_REDIRECT_URI_CONFIG = process.env.CALLBACK_URL || "";
export const FRONTEND_URL_CONFIG = process.env.FRONTEND_URL || "";

// Twitch API endpoints
export const TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token";
export const TWITCH_VALIDATE_URL = "https://id.twitch.tv/oauth2/validate";
export const TWITCH_HELIX_URL = "https://api.twitch.tv/helix";

// JWT configuration
export const JWT_SECRET = process.env.JWT_SECRET_KEY || "";

// Firestore collections
export const CHANNELS_COLLECTION = "managedChannels";
export const AUTO_CHAT_COLLECTION = "autoChatConfigs";
export const CHANNEL_COMMANDS_COLLECTION = "channelCommands";

// Internal bot configuration
export const WEBUI_INTERNAL_TOKEN = process.env.WEBUI_INTERNAL_TOKEN || "";
export const ALLOWED_CHANNELS_SECRET_NAME = process.env.ALLOWED_CHANNELS_SECRET_NAME || "";
export const BOT_PUBLIC_URL = process.env.BOT_PUBLIC_URL || "";
export const TWITCH_EVENTSUB_SECRET = process.env.TWITCH_EVENTSUB_SECRET || "";

// Environment flags
export const IS_PRODUCTION = process.env.NODE_ENV === "production";
export const IS_TEST = process.env.NODE_ENV === "test";

// CORS configuration
export const ALLOWED_ORIGINS = (() => {
  const origins = new Set([
    "http://127.0.0.1:5002",
    "http://localhost:5002",
  ]);

  if (FRONTEND_URL_CONFIG) {
    try {
      const url = new URL(FRONTEND_URL_CONFIG);
      origins.add(`${url.protocol}//${url.host}`);
    } catch {
      // Ignore parse error
    }
  }

  return Array.from(origins);
})();

// Rate limiting configuration
export const RATE_LIMIT = {
  AUTH: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per window
  },
  API: {
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // 60 requests per window
  },
};

// Available bot commands
export const ALL_COMMANDS = [
  "ask",
  "search",
  "game",
  "translate",
  "help",
  "lurk",
  "geo",
  "riddle",
  "trivia",
  "botlang",
  "auto",
  "disable",
  "enable",
  "ping",
  "quote",
];

// Auto-chat modes
export const AUTO_CHAT_MODES = ["off", "low", "medium", "high"] as const;

// Default auto-chat configuration
export const DEFAULT_AUTO_CHAT_CONFIG = {
  mode: "off" as const,
  categories: {
    greetings: true,
    facts: true,
    questions: true,
    celebrations: true,
    ads: false,
  },
};

// Token cache configuration
export const TOKEN_CACHE_BUFFER_SECONDS = 300; // 5 minutes before expiry

// App access token configuration
export const APP_TOKEN_REFRESH_BUFFER_MS = 3600000; // 1 hour buffer

// Token refresh configuration
export const TOKEN_REFRESH = {
  MAX_RETRY_ATTEMPTS: 3,
  RETRY_DELAY_MS: 5000,
};

// Request timeout
export const REQUEST_TIMEOUT_MS = 30000; // 30 seconds
