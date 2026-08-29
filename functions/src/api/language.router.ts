/**
 * Language router
 * Endpoints for the language the bot speaks in the channel.
 *
 * The same Firestore documents back the bot's `!botlang` command, so the two surfaces have to
 * agree on what a document means:
 *
 *   no document          the bot follows the channel's Twitch stream language ("automatic")
 *   { language: null }   an explicit choice of English, which detection must not override
 *   { language: "..." }  an explicit choice of that language
 *
 * That is why clearing the setting deletes the document rather than writing null.
 */

import { Router, Response } from "express";
import { getDb } from "@/config/database";
import { CHANNEL_LANGUAGES_COLLECTION, BOT_LANGUAGES } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { getChannelStreamLanguage } from "@/twitch";
import { tr } from "@/i18n";

const router = Router();

/** Twitch reports a stream language as a code; the bot stores languages by English name. */
const CODE_TO_LANGUAGE: Record<string, string> = {
  en: "english", es: "spanish", fr: "french", de: "german", ja: "japanese",
  pt: "portuguese", it: "italian", ru: "russian", zh: "chinese", ko: "korean",
  nl: "dutch", pl: "polish", tr: "turkish", ar: "arabic", hi: "hindi",
  vi: "vietnamese", th: "thai", sv: "swedish", da: "danish", no: "norwegian",
  fi: "finnish", el: "greek", cs: "czech", hu: "hungarian", ro: "romanian",
};

/**
 * The language a channel's Twitch setting implies, or null when it implies nothing.
 *
 * Mirrors the bot's rule exactly, including treating `en` as no signal: it is Twitch's default for
 * channels that never set one, so it is not evidence of intent.
 */
async function detectStreamLanguage(broadcasterId: string): Promise<string | null> {
  const code = await getChannelStreamLanguage(broadcasterId);
  if (!code) return null;
  const name = CODE_TO_LANGUAGE[code.split("-")[0]];
  return name && name !== "english" ? name : null;
}

/**
 * GET /api/language
 * Returns the channel's stored choice and what automatic detection currently resolves to.
 */
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const { userId, login } = req.user;
  // The bot keys these documents by lowercase login. Twitch logins already are, but the key is
  // shared across two repos, so pin it here rather than rely on that.
  const channelKey = login.toLowerCase();

  try {
    const [snap, detected] = await Promise.all([
      getDb().collection(CHANNEL_LANGUAGES_COLLECTION).doc(channelKey).get(),
      detectStreamLanguage(userId),
    ]);

    const data = snap.exists ? snap.data() : null;
    const stored = typeof data?.language === "string" && data.language.trim()
      ? data.language.trim().toLowerCase()
      : null;

    res.json({
      success: true,
      // `mode` carries the distinction a nullable `language` cannot: "auto" and an explicit
      // English choice both leave `language` null, but they behave differently.
      mode: snap.exists ? "manual" : "auto",
      language: stored,
      detected,
      available: BOT_LANGUAGES,
    });
  } catch (error) {
    logger.error("Error fetching bot language", {
      channelLogin: login,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.language.FailedLoadLanguageSetting", {}, "Failed to load language setting"),
    });
  }
});

/**
 * POST /api/language
 * Sets the language, or clears the setting so detection takes over again.
 *
 * Body: { language: "spanish" } | { language: null } (English) | { mode: "auto" }
 */
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const { login } = req.user;
  const channelKey = login.toLowerCase();

  try {
    const body = req.body || {};
    const docRef = getDb().collection(CHANNEL_LANGUAGES_COLLECTION).doc(channelKey);

    if (body.mode === "auto") {
      await docRef.delete();
      logger.info("Bot language set to automatic detection", { channelLogin: login });
      return res.json({
        success: true,
        mode: "auto",
        language: null,
        message: tr(req, "api.language.LanguageFollowsTwitchSetting", {}, "The bot now follows your Twitch stream language."),
      });
    }

    const raw = body.language;
    if (raw !== null && typeof raw !== "string") {
      return res.status(400).json({
        success: false,
        message: tr(req, "api.language.ChooseLanguage", {}, "Choose a language."),
      });
    }

    const name = typeof raw === "string" ? raw.trim().toLowerCase() : "";

    // English is stored as null, the way `!botlang off` stores it, so both surfaces read the same
    // document the same way.
    const language = name === "" || name === "english" ? null : name;

    if (language !== null && !(BOT_LANGUAGES as readonly string[]).includes(language)) {
      return res.status(400).json({
        success: false,
        message: tr(req, "api.language.LanguageNotAvailableHere", { language: name },
          `"${name}" is not one of the languages available here. A moderator can set any language with !botlang in chat.`),
      });
    }

    await docRef.set(
      {
        channelName: channelKey,
        language,
        updatedAt: new Date(),
      },
      { merge: true },
    );

    logger.info("Bot language saved", { channelLogin: login, language });
    res.json({
      success: true,
      mode: "manual",
      language,
      message: tr(req, "api.language.LanguageSaved", {}, "Bot language saved."),
    });
  } catch (error) {
    logger.error("Error saving bot language", {
      channelLogin: login,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: tr(req, "api.language.FailedSaveLanguageSetting", {}, "Failed to save language setting"),
    });
  }
});

export default router;
