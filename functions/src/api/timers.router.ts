/**
 * Timers router
 * CRUD endpoints for managing timed messages (periodic chat messages).
 * Mirrors the Firestore structure used by the bot:
 *   channelTimers/{channelName}/timers/{timerName}
 * The document contract is duplicated in the bot repo:
 *   twitch-knowledge-bot/src/components/timers/timersStorage.js
 * Keep field names, defaults, and validation limits in sync between the two.
 */

import { Router, Response } from "express";
import { getDb, FieldValue } from "@/config/database";
import { CHANNEL_TIMERS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { sanitizeTimerName } from "@/utils/validation";

const router = Router();

/** Valid timer types */
const VALID_TYPES = ["text", "prompt"];

/** Max number of timers per channel */
const MAX_TIMERS_PER_CHANNEL = 20;

/** Max response length in characters */
const MAX_RESPONSE_LENGTH = 500;

/** Interval bounds in minutes */
const MIN_INTERVAL_MINUTES = 2;
const MAX_INTERVAL_MINUTES = 1440;
const DEFAULT_INTERVAL_MINUTES = 15;

/** Chat-lines gate bounds */
const MAX_MIN_CHAT_LINES = 100;
const DEFAULT_MIN_CHAT_LINES = 5;

/** Names that collide with !timer subcommands in chat */
const RESERVED_TIMER_NAMES = [
  "add", "addai", "edit", "remove", "delete", "show", "list",
  "interval", "lines", "enable", "disable", "options", "help",
];

/**
 * Variables that depend on a triggering user — timers fire on their own,
 * so text timers must not use them (same list as the bot's
 * findUnsupportedTimerVariables in timersStorage.js).
 */
const UNSUPPORTED_TIMER_VARIABLES = [
  /\$\(user\)/i,
  /\$\(args\)/i,
  /\$\(\d+\)/,
  /\$\(followage\)/i,
  /\$\(pronouns?\)/i,
  /\$\(pronoun_[a-z]+\)/i,
  /\$\(checkin_count\)/i,
];

function findUnsupportedTimerVariables(template: string): string[] {
  const offenders: string[] = [];
  const matches = template.match(/\$\([^)]+\)/g) || [];
  for (const token of matches) {
    if (UNSUPPORTED_TIMER_VARIABLES.some((re) => re.test(token)) && !offenders.includes(token)) {
      offenders.push(token);
    }
  }
  return offenders;
}

/**
 * Validate a (already-sanitized) timer name.
 * Must be 1-25 lowercase alphanumeric + underscores and not a reserved word.
 */
function isValidTimerName(name: string): boolean {
  return /^[a-z0-9_]{1,25}$/.test(name) && !RESERVED_TIMER_NAMES.includes(name);
}

/**
 * Clamp-validate an integer field. Returns null when invalid.
 */
function parseIntInRange(value: unknown, min: number, max: number): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const int = Math.round(value);
  if (int < min || int > max) return null;
  return int;
}

/**
 * Helper: get the timers subcollection reference for a channel.
 */
function getTimersRef(channelName: string) {
  return getDb()
    .collection(CHANNEL_TIMERS_COLLECTION)
    .doc(channelName)
    .collection("timers");
}

// ─── GET /api/timers ─────────────────────────────────────────────────────────
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;

  try {
    const snapshot = await getTimersRef(channelLogin).orderBy("createdAt", "desc").get();

    const timers = snapshot.docs.map((doc) => ({
      name: doc.id,
      ...doc.data(),
    }));

    res.json({ success: true, timers });
  } catch (error) {
    logger.error("Error fetching timers", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error fetching timers",
    });
  }
});

// ─── POST /api/timers ────────────────────────────────────────────────────────
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;

  try {
    const { name: rawName, response, type, intervalMinutes, minChatLines } = req.body;

    // Sanitize then validate name
    const timerName = sanitizeTimerName(rawName);
    if (!timerName || !isValidTimerName(timerName)) {
      return res.status(400).json({
        success: false,
        message: "Timer name is required (letters, numbers, or underscores; reserved words not allowed).",
      });
    }

    // Validate response
    if (!response || typeof response !== "string" || response.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: "Message text is required.",
      });
    }

    if (response.length > MAX_RESPONSE_LENGTH) {
      return res.status(400).json({
        success: false,
        message: `Message must be ${MAX_RESPONSE_LENGTH} characters or fewer.`,
      });
    }

    // Validate type (optional, defaults to "text")
    const timerType = type || "text";
    if (!VALID_TYPES.includes(timerType)) {
      return res.status(400).json({
        success: false,
        message: `Invalid type. Must be one of: ${VALID_TYPES.join(", ")}`,
      });
    }

    // Text timers fire without a triggering user — reject user-dependent variables
    if (timerType === "text") {
      const offenders = findUnsupportedTimerVariables(response);
      if (offenders.length > 0) {
        return res.status(400).json({
          success: false,
          message: `These variables aren't supported in timers: ${offenders.join(", ")}`,
        });
      }
    }

    // Validate interval (optional, defaults to 15 minutes)
    const interval = intervalMinutes === undefined
      ? DEFAULT_INTERVAL_MINUTES
      : parseIntInRange(intervalMinutes, MIN_INTERVAL_MINUTES, MAX_INTERVAL_MINUTES);
    if (interval === null) {
      return res.status(400).json({
        success: false,
        message: `Interval must be between ${MIN_INTERVAL_MINUTES} and ${MAX_INTERVAL_MINUTES} minutes.`,
      });
    }

    // Validate chat-lines gate (optional, defaults to 5)
    const lines = minChatLines === undefined
      ? DEFAULT_MIN_CHAT_LINES
      : parseIntInRange(minChatLines, 0, MAX_MIN_CHAT_LINES);
    if (lines === null) {
      return res.status(400).json({
        success: false,
        message: `Min chat lines must be between 0 and ${MAX_MIN_CHAT_LINES}.`,
      });
    }

    // Check if timer already exists
    const docRef = getTimersRef(channelLogin).doc(timerName);
    const existing = await docRef.get();

    if (existing.exists) {
      return res.status(409).json({
        success: false,
        message: `Timer "${timerName}" already exists. Use edit to update it.`,
      });
    }

    // Check limit
    const countSnap = await getTimersRef(channelLogin).count().get();
    if (countSnap.data().count >= MAX_TIMERS_PER_CHANNEL) {
      return res.status(400).json({
        success: false,
        message: `Maximum of ${MAX_TIMERS_PER_CHANNEL} timers reached.`,
      });
    }

    await docRef.set({
      response: response.trim(),
      type: timerType,
      intervalMinutes: interval,
      minChatLines: lines,
      enabled: true,
      useCount: 0,
      lastRunAt: null,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      createdBy: channelLogin,
    });

    // Ensure the parent channel doc exists so the bot's loaders can list it
    await getDb()
      .collection(CHANNEL_TIMERS_COLLECTION)
      .doc(channelLogin)
      .set({ channelName: channelLogin, updatedAt: FieldValue.serverTimestamp() }, { merge: true });

    logger.info("Timer created", { channelLogin, timerName });

    res.json({
      success: true,
      message: `Timer "${timerName}" created.`,
    });
  } catch (error) {
    logger.error("Error creating timer", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error creating timer",
    });
  }
});

// ─── PUT /api/timers/:name ───────────────────────────────────────────────────
router.put("/:name", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const timerName = req.params.name?.trim().toLowerCase();

  if (!isValidTimerName(timerName)) {
    return res.status(400).json({
      success: false,
      message: "Invalid timer name.",
    });
  }

  try {
    const docRef = getTimersRef(channelLogin).doc(timerName);
    const existing = await docRef.get();

    if (!existing.exists) {
      return res.status(404).json({
        success: false,
        message: `Timer "${timerName}" does not exist.`,
      });
    }

    const updates: Record<string, unknown> = {
      updatedAt: FieldValue.serverTimestamp(),
    };

    // lastRunAt and useCount are bot-owned runtime state — never client-writable
    const { response, type, intervalMinutes, minChatLines, enabled } = req.body;

    if (type !== undefined) {
      if (!VALID_TYPES.includes(type)) {
        return res.status(400).json({
          success: false,
          message: `Invalid type. Must be one of: ${VALID_TYPES.join(", ")}`,
        });
      }
      updates.type = type;
    }

    if (response !== undefined) {
      if (typeof response !== "string" || response.trim().length === 0) {
        return res.status(400).json({
          success: false,
          message: "Message text cannot be empty.",
        });
      }
      if (response.length > MAX_RESPONSE_LENGTH) {
        return res.status(400).json({
          success: false,
          message: `Message must be ${MAX_RESPONSE_LENGTH} characters or fewer.`,
        });
      }
      // Validate against the type the timer will have after this update
      const effectiveType = (updates.type as string) || (existing.data()?.type ?? "text");
      if (effectiveType === "text") {
        const offenders = findUnsupportedTimerVariables(response);
        if (offenders.length > 0) {
          return res.status(400).json({
            success: false,
            message: `These variables aren't supported in timers: ${offenders.join(", ")}`,
          });
        }
      }
      updates.response = response.trim();
    }

    if (intervalMinutes !== undefined) {
      const interval = parseIntInRange(intervalMinutes, MIN_INTERVAL_MINUTES, MAX_INTERVAL_MINUTES);
      if (interval === null) {
        return res.status(400).json({
          success: false,
          message: `Interval must be between ${MIN_INTERVAL_MINUTES} and ${MAX_INTERVAL_MINUTES} minutes.`,
        });
      }
      updates.intervalMinutes = interval;
    }

    if (minChatLines !== undefined) {
      const lines = parseIntInRange(minChatLines, 0, MAX_MIN_CHAT_LINES);
      if (lines === null) {
        return res.status(400).json({
          success: false,
          message: `Min chat lines must be between 0 and ${MAX_MIN_CHAT_LINES}.`,
        });
      }
      updates.minChatLines = lines;
    }

    if (enabled !== undefined) {
      if (typeof enabled !== "boolean") {
        return res.status(400).json({
          success: false,
          message: "Enabled must be a boolean.",
        });
      }
      updates.enabled = enabled;
    }

    await docRef.update(updates);

    logger.info("Timer updated", { channelLogin, timerName });

    res.json({
      success: true,
      message: `Timer "${timerName}" updated.`,
    });
  } catch (error) {
    logger.error("Error updating timer", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error updating timer",
    });
  }
});

// ─── DELETE /api/timers/:name ────────────────────────────────────────────────
router.delete("/:name", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const timerName = req.params.name?.trim().toLowerCase();

  if (!isValidTimerName(timerName)) {
    return res.status(400).json({
      success: false,
      message: "Invalid timer name.",
    });
  }

  try {
    const docRef = getTimersRef(channelLogin).doc(timerName);
    const existing = await docRef.get();

    if (!existing.exists) {
      return res.status(404).json({
        success: false,
        message: `Timer "${timerName}" does not exist.`,
      });
    }

    await docRef.delete();

    logger.info("Timer deleted", { channelLogin, timerName });

    res.json({
      success: true,
      message: `Timer "${timerName}" deleted.`,
    });
  } catch (error) {
    logger.error("Error deleting timer", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error deleting timer",
    });
  }
});

export default router;
