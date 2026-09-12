/**
 * Preview router
 * Generates a sample AI response for an unsaved custom command, timer, or
 * check-in prompt, so the broadcaster can see what the bot would say before
 * saving.
 *
 * The inference itself runs on the bot (POST {BOT_PUBLIC_URL}/internal/preview),
 * not here: only the bot holds the channel persona cache, live stream/chat
 * context, the dedup history, and the production model routing. This router
 * authenticates the broadcaster, validates the input, and proxies with the
 * shared internal token. The channel always comes from the session JWT, never
 * from the request body.
 */

import { Router, Response } from "express";
import axios from "axios";
import { BOT_PUBLIC_URL } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { getInternalBotTokenValue } from "@/utils/secrets";
import { sanitizeTimerName } from "@/utils/validation";
import { tr } from "@/i18n";

const router = Router();

export const PREVIEW_KINDS = ["command", "timer", "checkin"] as const;
export type PreviewKind = (typeof PREVIEW_KINDS)[number];

/** Mirrors the save-side limits for AI prompt text. */
const MAX_PROMPT_LENGTH = 500;
const MAX_ARGS_LENGTH = 200;

/** A production inference with search grounding can take a while on a cold bot. */
const BOT_TIMEOUT_MS = 45_000;

export interface PreviewResult {
  kind: PreviewKind;
  resolvedPrompt: string;
  response: string | null;
  language: string | null;
}

// ─── POST /api/preview ───────────────────────────────────────────────────────
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const log = logger.child({ endpoint: "POST /api/preview", channelLogin });

  const { kind, prompt, name: rawName, args: rawArgs } = (req.body || {}) as {
    kind?: unknown;
    prompt?: unknown;
    name?: unknown;
    args?: unknown;
  };

  if (typeof kind !== "string" || !(PREVIEW_KINDS as readonly string[]).includes(kind)) {
    return res.status(400).json({
      success: false,
      message: tr(req, "api.preview.InvalidKind", {}, "Preview kind must be command, timer, or checkin."),
    });
  }
  if (typeof prompt !== "string" || prompt.trim() === "") {
    return res.status(400).json({
      success: false,
      message: tr(req, "api.preview.PromptRequired", {}, "Enter an AI prompt, then select Preview."),
    });
  }
  if (prompt.length > MAX_PROMPT_LENGTH) {
    return res.status(400).json({
      success: false,
      message: tr(req, "api.preview.PromptMust500", {}, "The AI prompt must be 500 characters or fewer."),
    });
  }
  if (rawArgs !== undefined && rawArgs !== null && (typeof rawArgs !== "string" || rawArgs.length > MAX_ARGS_LENGTH)) {
    return res.status(400).json({
      success: false,
      message: tr(req, "api.preview.ArgsMust200", {}, "The sample arguments must be 200 characters or fewer."),
    });
  }

  // The name only keys the dedup history on the bot; a malformed one is dropped
  // rather than rejected, since it is optional.
  const name = typeof rawName === "string" ? sanitizeTimerName(rawName) : "";
  const args = kind === "command" && typeof rawArgs === "string" ? rawArgs.trim() : "";

  if (!BOT_PUBLIC_URL) {
    log.warn("BOT_PUBLIC_URL not configured; preview unavailable");
    return res.status(503).json({
      success: false,
      message: tr(req, "api.preview.NotConfigured", {}, "Preview is not available right now."),
    });
  }

  try {
    const internalToken = await getInternalBotTokenValue();
    const botRes = await axios.post<{ success: boolean; preview?: PreviewResult; message?: string }>(
      `${BOT_PUBLIC_URL}/internal/preview`,
      {
        channel: channelLogin,
        kind,
        prompt: prompt.trim(),
        ...(name ? { name } : {}),
        ...(args ? { args } : {}),
      },
      {
        headers: { Authorization: `Bearer ${internalToken}` },
        timeout: BOT_TIMEOUT_MS,
        // Let 4xx/5xx through so the branches below can distinguish them.
        validateStatus: () => true,
      },
    );

    if (botRes.status !== 200 || !botRes.data?.success || !botRes.data.preview) {
      log.error("Bot rejected preview request", {
        status: botRes.status,
        botMessage: botRes.data?.message,
        kind,
      });
      const unavailable = botRes.status === 503 || botRes.status === 404;
      return res.status(unavailable ? 503 : 502).json({
        success: false,
        message: unavailable
          ? tr(req, "api.preview.NotConfigured", {}, "Preview is not available right now.")
          : tr(req, "api.preview.Failed", {}, "The preview failed. Try again."),
      });
    }

    const preview = botRes.data.preview;
    if (!preview.response) {
      return res.status(200).json({
        success: false,
        preview,
        message: tr(req, "api.preview.NoResponse", {}, "The AI did not return a response. Try again, or change the prompt."),
      });
    }

    log.info("Preview generated", { kind, responseLength: preview.response.length });
    return res.json({ success: true, preview });
  } catch (error) {
    const e = error as Error & { code?: string };
    const unreachable = axios.isAxiosError(e) && !e.response;
    log.error("Error generating preview", { error: e.message, code: e.code, kind });
    return res.status(unreachable ? 503 : 500).json({
      success: false,
      message: unreachable
        ? tr(req, "api.preview.BotUnavailable", {}, "The bot did not respond. Wait one minute, then try again.")
        : tr(req, "api.preview.Failed", {}, "The preview failed. Try again."),
    });
  }
});

export default router;
