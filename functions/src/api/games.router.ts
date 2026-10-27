/**
 * Games router
 * Endpoints for the chat game configs (trivia, geo, riddle).
 * Documents: {trivia,geo,riddle}GameConfigs/{broadcasterId}, keyed by
 * broadcaster ID, not login (see utils/channelKey). The bot owns them and
 * listens for changes, so a write here applies at the channel's next question
 * or round. `channelName` is stored for readability only.
 */

import { Router, Response } from "express";
import { getDb } from "@/config/database";
import {
  GAME_CONFIGS,
  GAME_IDS,
  GAME_LIST_MAX_ITEMS,
  GAME_LIST_MAX_LENGTH,
  GameConfigSpec,
  GameFieldSpec,
  GameId,
} from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { channelDocKey } from "@/utils/channelKey";
import { tr } from "@/i18n";

const router = Router();

type GameConfig = Record<string, unknown>;

function isGameId(value: string): value is GameId {
  return (GAME_IDS as readonly string[]).includes(value);
}

/**
 * The dashboard's view of a stored config: the defaults, then the stored
 * values that have the right type. Hidden fields and bad values are left out.
 */
function publicConfig(spec: GameConfigSpec, stored: GameConfig | undefined): GameConfig {
  const config: GameConfig = {};
  for (const [field, fieldSpec] of Object.entries(spec.fields)) {
    const value = stored?.[field];
    const parsed = value === undefined ? undefined : parseField(fieldSpec, value);
    config[field] = parsed && parsed.ok ? parsed.value : spec.defaults[field];
  }
  return config;
}

type ParseResult = { ok: true; value: unknown } | { ok: false };

function parseField(spec: GameFieldSpec, value: unknown): ParseResult {
  switch (spec.type) {
  case "enum":
    return typeof value === "string" && spec.values.includes(value) ?
      { ok: true, value } :
      { ok: false };
  case "int":
    return Number.isInteger(value) && (value as number) >= spec.min && (value as number) <= spec.max ?
      { ok: true, value } :
      { ok: false };
  case "bool":
    return typeof value === "boolean" ? { ok: true, value } : { ok: false };
  case "list": {
    if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
      return { ok: false };
    }
    // Trim, drop empty entries and drop repeats (case-insensitive, first one wins).
    const seen = new Set<string>();
    const items: string[] = [];
    for (const raw of value as string[]) {
      const item = raw.trim();
      if (!item || seen.has(item.toLowerCase())) continue;
      seen.add(item.toLowerCase());
      items.push(item);
    }
    if (items.length > GAME_LIST_MAX_ITEMS || items.some((item) => item.length > GAME_LIST_MAX_LENGTH)) {
      return { ok: false };
    }
    return { ok: true, value: items };
  }
  }
}

function invalidFieldMessage(req: AuthenticatedRequest, field: string, spec: GameFieldSpec): string {
  switch (spec.type) {
  case "enum":
    return tr(req, "api.games.InvalidChoice", { field, values: spec.values.join(", ") },
      `${field} must be one of: ${spec.values.join(", ")}.`);
  case "int":
    return tr(req, "api.games.InvalidNumber", { field, min: spec.min, max: spec.max },
      `${field} must be a whole number from ${spec.min} to ${spec.max}.`);
  case "bool":
    return tr(req, "api.games.InvalidSwitch", { field }, `${field} must be true or false.`);
  case "list":
    return tr(req, "api.games.InvalidList", {
      field, maxItems: GAME_LIST_MAX_ITEMS, maxLength: GAME_LIST_MAX_LENGTH,
    }, `${field} must be a list of up to ${GAME_LIST_MAX_ITEMS} names. ` +
      `Each name can have up to ${GAME_LIST_MAX_LENGTH} characters.`);
  }
}

/**
 * Sends a 400 for an unknown game and returns null, or returns the game's spec.
 */
function gameSpecOr400(req: AuthenticatedRequest, res: Response): [GameId, GameConfigSpec] | null {
  const game = String(req.params.game || "").toLowerCase();
  if (!isGameId(game)) {
    res.status(400).json({
      success: false,
      message: tr(req, "api.games.UnknownGame", { game, games: GAME_IDS.join(", ") },
        `"${game}" is not a game. Use one of: ${GAME_IDS.join(", ")}.`),
    });
    return null;
  }
  return [game, GAME_CONFIGS[game]];
}

/**
 * GET /api/games
 * Get the config of every game for the authenticated user's channel
 */
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const channelKey = channelDocKey(req.user);
  const db = getDb();

  try {
    const snaps = await Promise.all(
      GAME_IDS.map((game) => db.collection(GAME_CONFIGS[game].collection).doc(channelKey).get()),
    );
    const games: Record<string, GameConfig> = {};
    GAME_IDS.forEach((game, i) => {
      const snap = snaps[i];
      games[game] = publicConfig(GAME_CONFIGS[game], snap.exists ? snap.data() : undefined);
    });

    res.json({ success: true, games });
  } catch (error) {
    logger.error("Error fetching game configs", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.games.FailedLoadGames", {}, "The game settings did not load. Try again."),
    });
  }
});

/**
 * POST /api/games/:game
 * Update a game's config (partial updates supported)
 */
router.post("/:game", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const target = gameSpecOr400(req, res);
  if (!target) return;
  const [game, spec] = target;

  const body = req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};
  const updates: GameConfig = {};
  for (const [field, value] of Object.entries(body)) {
    // Own properties only: "constructor" or "__proto__" would otherwise reach Object and its prototype
    const fieldSpec = Object.prototype.hasOwnProperty.call(spec.fields, field) ? spec.fields[field] : undefined;
    if (!fieldSpec) {
      return res.status(400).json({
        success: false,
        message: tr(req, "api.games.UnknownSetting", { field }, `"${field}" is not a setting for this game.`),
      });
    }
    const parsed = parseField(fieldSpec, value);
    if (!parsed.ok) {
      return res.status(400).json({ success: false, message: invalidFieldMessage(req, field, fieldSpec) });
    }
    updates[field] = parsed.value;
  }
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({
      success: false,
      message: tr(req, "api.games.NoSettings", {}, "Send at least one setting to change."),
    });
  }

  try {
    const channelKey = channelDocKey(req.user);
    const docRef = getDb().collection(spec.collection).doc(channelKey);
    const existingSnap = await docRef.get();
    const existing = existingSnap.exists ? existingSnap.data() : undefined;

    await docRef.set({ channelName: channelLogin, updatedAt: new Date(), ...updates }, { merge: true });

    logger.info("Game config updated", { channelLogin, game, updates });
    res.json({ success: true, game, config: publicConfig(spec, { ...existing, ...updates }) });
  } catch (error) {
    logger.error("Error saving game config", {
      channelLogin,
      game,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.games.FailedSaveGame", {}, "The game settings did not save. Try again."),
    });
  }
});

/**
 * POST /api/games/:game/reset
 * Put every setting of a game back to its default, as `!<game> resetconfig` does
 */
router.post("/:game/reset", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const target = gameSpecOr400(req, res);
  if (!target) return;
  const [game, spec] = target;

  try {
    const channelKey = channelDocKey(req.user);
    await getDb().collection(spec.collection).doc(channelKey).set(
      { channelName: channelLogin, updatedAt: new Date(), ...spec.defaults },
      { merge: true },
    );

    logger.info("Game config reset", { channelLogin, game });
    res.json({ success: true, game, config: publicConfig(spec, spec.defaults) });
  } catch (error) {
    logger.error("Error resetting game config", {
      channelLogin,
      game,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.games.FailedSaveGame", {}, "The game settings did not save. Try again."),
    });
  }
});

export default router;
