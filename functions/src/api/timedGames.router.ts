/**
 * Timed games router
 * Endpoints for the chat games that the bot starts on its own at a fixed interval.
 * Documents: timedGameConfigs/{broadcasterId}, keyed by broadcaster ID, not
 * login (see utils/channelKey). `channelName` is stored for readability only.
 *
 * The bot reads these documents with a listener (src/components/timedGames/
 * timedGamesStorage.js in twitch-knowledge-bot) and writes `lastRunAt` and
 * `lastGame` to them. This router writes only the settings.
 */

import { Router, Response } from "express";
import { getDb } from "@/config/database";
import {
  TIMED_GAMES_COLLECTION,
  TIMED_GAMES_MIN_INTERVAL_MINUTES,
  TIMED_GAMES_MAX_INTERVAL_MINUTES,
  DEFAULT_TIMED_GAMES_CONFIG,
  GAME_IDS,
  GameId,
} from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { channelDocKey } from "@/utils/channelKey";
import { tr } from "@/i18n";

const router = Router();

interface TimedGamesConfig {
  enabled: boolean;
  intervalMinutes: number;
  games: GameId[];
}

function isValidInterval(value: unknown): value is number {
  return Number.isInteger(value)
    && (value as number) >= TIMED_GAMES_MIN_INTERVAL_MINUTES
    && (value as number) <= TIMED_GAMES_MAX_INTERVAL_MINUTES;
}

/** Returns the known games from `value` in canonical order, or null when `value` is not a list of known games. */
function parseGames(value: unknown): GameId[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  if (!value.every((g) => typeof g === "string" && (GAME_IDS as readonly string[]).includes(g))) return null;
  return GAME_IDS.filter((id) => value.includes(id));
}

/** Merges a stored document over the defaults, dropping values of the wrong type. */
function publicConfig(data: Record<string, unknown> | undefined): TimedGamesConfig {
  const d = data || {};
  return {
    enabled: d.enabled === true,
    intervalMinutes: isValidInterval(d.intervalMinutes)
      ? d.intervalMinutes
      : DEFAULT_TIMED_GAMES_CONFIG.intervalMinutes,
    games: parseGames(d.games) || [...DEFAULT_TIMED_GAMES_CONFIG.games],
  };
}

/**
 * GET /api/timed-games
 * Returns the timed games settings for the authenticated user's channel.
 */
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  try {
    const snap = await getDb().collection(TIMED_GAMES_COLLECTION).doc(channelDocKey(req.user)).get();
    res.json({
      success: true,
      config: publicConfig(snap.exists ? snap.data() : undefined),
      limits: {
        minIntervalMinutes: TIMED_GAMES_MIN_INTERVAL_MINUTES,
        maxIntervalMinutes: TIMED_GAMES_MAX_INTERVAL_MINUTES,
      },
    });
  } catch (error) {
    logger.error("Error fetching timed games config", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.timedGames.FailedLoad", {}, "The timed games settings did not load. Try again."),
    });
  }
});

/**
 * POST /api/timed-games
 * Partial update: send any of `enabled`, `intervalMinutes` and `games`.
 */
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const updates: Partial<TimedGamesConfig> = {};

  if (body.enabled !== undefined) {
    if (typeof body.enabled !== "boolean") {
      return res.status(400).json({
        success: false,
        message: tr(req, "api.timedGames.InvalidEnabled", {}, "enabled must be true or false."),
      });
    }
    updates.enabled = body.enabled;
  }

  if (body.intervalMinutes !== undefined) {
    if (!isValidInterval(body.intervalMinutes)) {
      const min = TIMED_GAMES_MIN_INTERVAL_MINUTES;
      const max = TIMED_GAMES_MAX_INTERVAL_MINUTES;
      return res.status(400).json({
        success: false,
        message: tr(req, "api.timedGames.InvalidInterval", { min, max },
          `The interval must be a whole number of minutes from ${min} to ${max}.`),
      });
    }
    updates.intervalMinutes = body.intervalMinutes;
  }

  if (body.games !== undefined) {
    const games = parseGames(body.games);
    if (!games) {
      const list = GAME_IDS.join(", ");
      return res.status(400).json({
        success: false,
        message: tr(req, "api.timedGames.InvalidGames", { games: list },
          `Select one or more of these games: ${list}.`),
      });
    }
    updates.games = games;
  }

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({
      success: false,
      message: tr(req, "api.timedGames.NoSettings", {}, "Send at least one setting to change."),
    });
  }

  try {
    const docRef = getDb().collection(TIMED_GAMES_COLLECTION).doc(channelDocKey(req.user));
    await docRef.set({ channelName: channelLogin, updatedAt: new Date(), ...updates }, { merge: true });
    logger.info("Timed games config updated", { channelLogin, updates });

    const snap = await docRef.get();
    res.json({ success: true, config: publicConfig(snap.exists ? snap.data() : undefined) });
  } catch (error) {
    logger.error("Error saving timed games config", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.timedGames.FailedSave", {}, "The timed games settings did not save. Try again."),
    });
  }
});

export default router;
