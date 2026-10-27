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
export const CUSTOM_COMMANDS_COLLECTION = "customCommands";
export const CHANNEL_TIMERS_COLLECTION = "channelTimers";

// Per-channel bot response language, written by both this dashboard and the bot's `!botlang`
// command. Keyed by broadcaster ID (utils/channelKey), as the bot keys it. A missing document is not the same as one
// holding `language: null`: no document hands the channel to Twitch stream-language detection,
// while `null` is an explicit choice of English that detection must not override.
export const CHANNEL_LANGUAGES_COLLECTION = "channelLanguages";

// Single-use codes exchanged for a session token after OAuth. Short-lived by
// design; a Firestore TTL policy on `expiresAt` collects abandoned rows.
export const EXCHANGE_CODES_COLLECTION = "authExchangeCodes";
export const EXCHANGE_CODE_TTL_MS = 60 * 1000;

// Internal bot configuration
export const WEBUI_INTERNAL_TOKEN = process.env.WEBUI_INTERNAL_TOKEN || "";
export const ALLOWED_CHANNELS_SECRET_NAME = process.env.ALLOWED_CHANNELS_SECRET_NAME || "";
export const BOT_PUBLIC_URL = process.env.BOT_PUBLIC_URL || "";
export const TWITCH_EVENTSUB_SECRET = process.env.TWITCH_EVENTSUB_SECRET || "";

// Custom bot personas, keyed by immutable Twitch broadcaster ID rather than
// login name: Twitch lets users rename and eventually releases old names, so a
// name-keyed persona could be inherited by a later registrant of that name.
export const PERSONA_COLLECTION = "channelPersonas";

// Written by the bot at startup, holding the authoritative default persona,
// immutable core, and length limit. Read-only from this side — it exists so the
// dashboard never keeps its own copy of that text.
export const BOT_DEFAULTS_COLLECTION = "botDefaults";
export const BOT_DEFAULTS_DOC = "persona";

// Safety screening for broadcaster-authored prompt text.
export const GEMINI_API_KEY_SECRET = process.env.GEMINI_API_KEY_SECRET || "";
export const GEMINI_SAFETY_MODEL = process.env.GEMINI_SAFETY_MODEL || "gemini-flash-lite-latest";

// Environment flags
export const IS_PRODUCTION = process.env.NODE_ENV === "production";
export const IS_TEST = process.env.NODE_ENV === "test";

// CORS configuration
export const ALLOWED_ORIGINS = (() => {
  const origins = new Set([
    "http://127.0.0.1:5002",
    "http://localhost:5002",
    "https://app.wildcat.chat",
    "https://bot.wildcat.chat",
    "https://streamsage-bot.web.app",
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
    // Keyed by IP, and these routes carry no credential to brute-force — they
    // build a Twitch redirect and exchange a single-use code. The old limit of
    // 10 locked out everyone sharing a NAT (offices, dorms, carrier CGNAT).
    max: 60,
  },
  API: {
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // 60 requests per window
  },
  // Routes that run an LLM safety check on save. Each request costs a Gemini
  // call, so these are limited far more tightly than ordinary config writes —
  // and keyed per user rather than per IP, since the JWT identifies the caller.
  PROMPT_WRITE: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20,
  },
  // Dashboard "Preview" runs a full production-grade inference on the bot
  // (main-tier model plus search grounding), so it gets its own, tighter budget.
  PREVIEW: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 12,
  },
};

// Twitch OAuth scopes that the dashboard requests from a broadcaster. The bot uses this token
// when it is not a moderator in the channel, for announcements and for the Shoutout from !so.
// The bot account requests its own list in the bot's scripts/get-user-token.js.
export const TWITCH_OAUTH_SCOPES: readonly string[] = [
  "user:read:email",
  "channel:read:ads",
  "channel:read:subscriptions",
  "channel:manage:moderators",
  "moderator:read:followers",
  "channel:manage:redemptions",
  "moderator:manage:announcements",
  "moderator:manage:shoutouts",
];

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
  "command",
  "followage",
  "so",
  "timer",
  "remember",
  "forget",
  "forgetme",
  "memory",
];

// Commands a channel cannot turn off: !enable and !disable so moderators can always re-enable a
// command from chat, and !forgetme so a viewer can always opt out of channel memory. Mirrors
// PROTECTED_COMMANDS in the bot's src/components/context/commandStateManager.js, which also
// ignores a stored disable for these; change both together.
export const ALWAYS_ON_COMMANDS: readonly string[] = ["enable", "disable", "forgetme"];

// Options that the dashboard stores for a built-in command, with their defaults. They live in
// channelCommands/{broadcasterId} as commandOptions.{command}.{option}, and the bot reads them with
// getCommandOptions() in src/components/context/channelCommandsStorage.js; change both together.
// !so: aiMessage writes the shoutout line with the AI, twitchShoutout also sends the Twitch Shoutout.
export const COMMAND_OPTION_DEFAULTS: Readonly<Record<string, Readonly<Record<string, boolean>>>> = {
  so: { aiMessage: true, twitchShoutout: true },
};


// Languages the dashboard offers for bot responses, stored as the lowercase English name the bot
// keeps in Firestore. Mirrors COMMON_LANGUAGES in the bot's translationUtils.js — the two repos
// share Firestore rather than code, so this list has to be kept in step with that one by hand.
//
// The first eight have written translations committed in the bot, so their fixed messages are
// instant and worded the same every time. The rest are translated per message as the bot sends
// them. `!botlang` accepts free text, so a channel can hold a language outside this list; the
// dashboard shows such a value rather than silently replacing it.
export const BOT_LANGUAGES = [
  "english",
  "spanish",
  "french",
  "german",
  "italian",
  "portuguese",
  "japanese",
  "russian",
  "chinese",
  "korean",
  "dutch",
  "polish",
  "turkish",
  "arabic",
  "hindi",
  "vietnamese",
  "thai",
  "swedish",
  "danish",
  "norwegian",
  "finnish",
  "greek",
  "czech",
  "hungarian",
  "romanian",
] as const;


// Auto-chat modes
export const AUTO_CHAT_MODES = ["off", "low", "medium", "high"] as const;

// Default auto-chat configuration
export const DEFAULT_AUTO_CHAT_CONFIG = {
  mode: "off" as const,
  categories: {
    greetings: true,
    facts: true,
    questions: true,
    follows: true,
    subscriptions: true,
    raids: true,
    ads: false,
  },
};

// Chat game configs. The bot owns these documents: each game reads its config
// at the first game in a channel and listens for changes after that. Keyed by
// broadcaster ID (utils/channelKey), as the bot keys them. The defaults and the
// limits below copy the bot's DEFAULT_CONFIG and configureGame checks in
// src/components/{trivia,geo,riddle}/*GameManager.js; change both together.
export const GAME_IDS = ["trivia", "geo", "riddle"] as const;
export type GameId = (typeof GAME_IDS)[number];

export const GAME_DIFFICULTIES = ["easy", "normal", "hard"] as const;

// Limits for the list settings (topics, regions, game titles).
export const GAME_LIST_MAX_ITEMS = 20;
export const GAME_LIST_MAX_LENGTH = 60;

export type GameFieldSpec =
  | { type: "enum"; values: readonly string[] }
  | { type: "int"; min: number; max: number }
  | { type: "bool" }
  | { type: "list" };

export interface GameConfigSpec {
  collection: string;
  // Every default the bot's `!<game> resetconfig` writes, including the ones
  // the dashboard does not show.
  defaults: Record<string, unknown>;
  // The settings the dashboard reads and writes.
  fields: Record<string, GameFieldSpec>;
}

const SCORING_FIELDS: Record<string, GameFieldSpec> = {
  pointsTimeBonus: { type: "bool" },
  pointsDifficultyMultiplier: { type: "bool" },
  scoreTracking: { type: "bool" },
};

export const GAME_CONFIGS: Record<GameId, GameConfigSpec> = {
  trivia: {
    collection: "triviaGameConfigs",
    defaults: {
      difficulty: "normal",
      questionTimeSeconds: 45,
      roundDurationMinutes: 2,
      scoreTracking: true,
      topicPreferences: [],
      pointsBase: 10,
      pointsTimeBonus: true,
      pointsDifficultyMultiplier: true,
    },
    fields: {
      difficulty: { type: "enum", values: GAME_DIFFICULTIES },
      questionTimeSeconds: { type: "int", min: 10, max: 120 },
      pointsBase: { type: "int", min: 1, max: 100 },
      ...SCORING_FIELDS,
      topicPreferences: { type: "list" },
    },
  },
  geo: {
    collection: "geoGameConfigs",
    defaults: {
      difficulty: "normal",
      clueIntervalSeconds: 45,
      roundDurationMinutes: 5,
      scoreTracking: true,
      pointsBase: 15,
      pointsTimeBonus: true,
      pointsDifficultyMultiplier: true,
      regionRestrictions: [],
      gameTitlePreferences: [],
    },
    fields: {
      difficulty: { type: "enum", values: GAME_DIFFICULTIES },
      clueIntervalSeconds: { type: "int", min: 30, max: 300 },
      roundDurationMinutes: { type: "int", min: 3, max: 20 },
      pointsBase: { type: "int", min: 1, max: 100 },
      ...SCORING_FIELDS,
      regionRestrictions: { type: "list" },
      gameTitlePreferences: { type: "list" },
    },
  },
  riddle: {
    collection: "riddleGameConfigs",
    defaults: {
      difficulty: "normal",
      questionTimeSeconds: 45,
      pointsBase: 15,
      pointsTimeBonus: true,
      pointsDifficultyMultiplier: true,
      scoreTracking: true,
      maxRounds: 10,
      recentKeywordsFetchLimit: 50,
      multiRoundDelayMs: 12000,
      maxRiddleGenerationRetries: 3,
    },
    fields: {
      difficulty: { type: "enum", values: GAME_DIFFICULTIES },
      questionTimeSeconds: { type: "int", min: 15, max: 120 },
      pointsBase: { type: "int", min: 1, max: 1000 },
      ...SCORING_FIELDS,
      // The bot accepts up to 20, but a chat command never starts more than 10 rounds.
      maxRounds: { type: "int", min: 1, max: 10 },
      multiRoundDelayMs: { type: "int", min: 1000, max: 60000 },
    },
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
