/**
 * Persona router
 * Endpoints for the channel's custom bot personality (system instruction).
 *
 * Documents are keyed by immutable Twitch broadcaster ID, not login name — see
 * PERSONA_COLLECTION in config/constants for why.
 */

import { Router, Response } from "express";
import { getDb } from "@/config/database";
import {
  PERSONA_COLLECTION,
  BOT_DEFAULTS_COLLECTION,
  BOT_DEFAULTS_DOC,
} from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { screenPromptField } from "@/utils/promptSafety";

const router = Router();

/**
 * Bootstrap fallback, used ONLY when the bot has not yet published
 * botDefaults/persona (first deploy, or the bot has never started against this
 * project). The bot's DEFAULT_BOT_PERSONA is the source of truth; this copy
 * exists so the dashboard is not blank in that window, and responses carry
 * isFallback:true so the UI can say so.
 */
const FALLBACK_PERSONA =
  "You are a witty and knowledgeable regular in this Twitch stream who happens to be a bot.\n\n" +
  "Tone: Clever, warm, and snarky yet good-natured. Ultimately, you're a supportive friend.";
const FALLBACK_MAX_LENGTH = 2000;

interface BotDefaults {
  persona: string;
  core: string;
  maxLength: number;
  isFallback: boolean;
}

/**
 * Reads the bot-published defaults. Never throws — a missing or unreadable
 * document degrades to the bootstrap copy rather than failing the request.
 */
async function getBotDefaults(): Promise<BotDefaults> {
  try {
    const snap = await getDb()
      .collection(BOT_DEFAULTS_COLLECTION)
      .doc(BOT_DEFAULTS_DOC)
      .get();

    if (snap.exists) {
      const data = snap.data() || {};
      if (typeof data.persona === "string" && data.persona.trim()) {
        return {
          persona: data.persona,
          core: typeof data.core === "string" ? data.core : "",
          maxLength: typeof data.maxLength === "number" ? data.maxLength : FALLBACK_MAX_LENGTH,
          isFallback: false,
        };
      }
    }
  } catch (error) {
    logger.error("Could not read bot defaults", { error: (error as Error).message });
  }

  return {
    persona: FALLBACK_PERSONA,
    core: "",
    maxLength: FALLBACK_MAX_LENGTH,
    isFallback: true,
  };
}

/**
 * GET /api/persona
 * Returns the channel's custom persona, or the bot's default as editable
 * boilerplate when none is set.
 */
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const { userId, login } = req.user;

  try {
    const [defaults, snap] = await Promise.all([
      getBotDefaults(),
      getDb().collection(PERSONA_COLLECTION).doc(userId).get(),
    ]);

    const data = snap.exists ? snap.data() : null;
    const custom =
      data && data.status === "approved" && typeof data.instructions === "string"
        ? data.instructions
        : null;

    res.json({
      success: true,
      instructions: custom || defaults.persona,
      core: defaults.core,
      isDefault: !custom,
      isFallback: defaults.isFallback,
      maxLength: defaults.maxLength,
      updatedAt: data?.updatedAt || null,
    });
  } catch (error) {
    logger.error("Error fetching persona", {
      channelLogin: login,
      error: (error as Error).message,
    });
    res.status(500).json({ success: false, message: "Failed to load personality settings" });
  }
});

/**
 * POST /api/persona
 * Saves a custom persona, after safety screening. Rejected text is not persisted.
 */
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const { userId, login } = req.user;

  try {
    const instructions = req.body?.instructions;

    if (typeof instructions !== "string" || instructions.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: "Personality instructions cannot be empty.",
      });
    }

    const trimmed = instructions.trim();
    const { maxLength } = await getBotDefaults();

    // Cheap validation first, so a payload that cannot be saved anyway never
    // costs an LLM call.
    if (trimmed.length > maxLength) {
      return res.status(400).json({
        success: false,
        message: `Personality instructions must be ${maxLength} characters or fewer.`,
      });
    }

    const rejection = await screenPromptField(trimmed, "persona");
    if (rejection) {
      logger.info("Persona save rejected", { channelLogin: login, status: rejection.status });
      return res.status(rejection.status).json(rejection.body);
    }

    await getDb().collection(PERSONA_COLLECTION).doc(userId).set(
      {
        twitchUserId: userId,
        // Denormalized for debugging only. Never used as a key — it can go stale
        // when a broadcaster renames on Twitch.
        channelName: login,
        instructions: trimmed,
        status: "approved",
        reviewedAt: new Date(),
        updatedAt: new Date(),
      },
      { merge: true },
    );

    logger.info("Persona saved", { channelLogin: login, length: trimmed.length });
    res.json({ success: true, message: "Personality saved." });
  } catch (error) {
    logger.error("Error saving persona", {
      channelLogin: login,
      error: (error as Error).message,
    });
    res.status(500).json({ success: false, message: "Failed to save personality settings" });
  }
});

/**
 * DELETE /api/persona
 * Clears the custom persona, reverting the channel to the bot's default.
 */
router.delete("/", async (req: AuthenticatedRequest, res: Response) => {
  const { userId, login } = req.user;

  try {
    await getDb().collection(PERSONA_COLLECTION).doc(userId).delete();
    logger.info("Persona reset to default", { channelLogin: login });
    res.json({ success: true, message: "Personality reset to default." });
  } catch (error) {
    logger.error("Error deleting persona", {
      channelLogin: login,
      error: (error as Error).message,
    });
    res.status(500).json({ success: false, message: "Failed to reset personality" });
  }
});

export default router;
