/**
 * Custom Commands router
 * CRUD endpoints for managing user-defined custom commands.
 * Mirrors the Firestore structure used by the bot:
 *   customCommands/{channelName}/commands/{commandName}
 */

import { Router, Response } from "express";
import { getDb, FieldValue } from "@/config/database";
import { CUSTOM_COMMANDS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";

const router = Router();

/** Valid permission levels (must match the bot's expectations) */
const VALID_PERMISSIONS = ["everyone", "subscriber", "vip", "moderator", "broadcaster"];

/** Max number of custom commands per channel */
const MAX_COMMANDS_PER_CHANNEL = 100;

/** Max response length in characters */
const MAX_RESPONSE_LENGTH = 500;

/**
 * Validate a command name.
 * Must be 1-25 lowercase alphanumeric + underscores, no leading !
 */
function isValidCommandName(name: unknown): name is string {
  if (!name || typeof name !== "string") return false;
  const trimmed = name.trim().toLowerCase();
  return /^[a-z0-9_]{1,25}$/.test(trimmed);
}

/**
 * Helper: get the commands subcollection reference for a channel.
 */
function getCommandsRef(channelName: string) {
  return getDb()
    .collection(CUSTOM_COMMANDS_COLLECTION)
    .doc(channelName)
    .collection("commands");
}

// ─── GET /api/custom-commands ────────────────────────────────────────────────
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;

  try {
    const snapshot = await getCommandsRef(channelLogin).orderBy("createdAt", "desc").get();

    const commands = snapshot.docs.map((doc) => ({
      name: doc.id,
      ...doc.data(),
    }));

    res.json({ success: true, commands });
  } catch (error) {
    logger.error("Error fetching custom commands", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error fetching custom commands",
    });
  }
});

// ─── POST /api/custom-commands ───────────────────────────────────────────────
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;

  try {
    const { name, response, permission, cooldown } = req.body;

    // Validate name
    if (!isValidCommandName(name)) {
      return res.status(400).json({
        success: false,
        message: "Invalid command name. Use 1-25 lowercase letters, numbers, or underscores.",
      });
    }

    const commandName = (name as string).trim().toLowerCase();

    // Validate response
    if (!response || typeof response !== "string" || response.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: "Response text is required.",
      });
    }

    if (response.length > MAX_RESPONSE_LENGTH) {
      return res.status(400).json({
        success: false,
        message: `Response must be ${MAX_RESPONSE_LENGTH} characters or fewer.`,
      });
    }

    // Validate permission (optional, defaults to "everyone")
    const perm = permission || "everyone";
    if (!VALID_PERMISSIONS.includes(perm)) {
      return res.status(400).json({
        success: false,
        message: `Invalid permission. Must be one of: ${VALID_PERMISSIONS.join(", ")}`,
      });
    }

    // Validate cooldown (optional, defaults to 5000ms)
    const cooldownMs = typeof cooldown === "number" ? Math.max(0, Math.min(300000, cooldown)) : 5000;

    // Check if command already exists
    const docRef = getCommandsRef(channelLogin).doc(commandName);
    const existing = await docRef.get();

    if (existing.exists) {
      return res.status(409).json({
        success: false,
        message: `Command !${commandName} already exists. Use edit to update it.`,
      });
    }

    // Check limit
    const countSnap = await getCommandsRef(channelLogin).count().get();
    if (countSnap.data().count >= MAX_COMMANDS_PER_CHANNEL) {
      return res.status(400).json({
        success: false,
        message: `Maximum of ${MAX_COMMANDS_PER_CHANNEL} custom commands reached.`,
      });
    }

    await docRef.set({
      response: response.trim(),
      permission: perm,
      cooldownMs,
      enabled: true,
      useCount: 0,
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      createdBy: channelLogin,
    });

    logger.info("Custom command created", { channelLogin, commandName });

    res.json({
      success: true,
      message: `Command !${commandName} created.`,
    });
  } catch (error) {
    logger.error("Error creating custom command", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error creating custom command",
    });
  }
});

// ─── PUT /api/custom-commands/:name ──────────────────────────────────────────
router.put("/:name", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const commandName = req.params.name?.trim().toLowerCase();

  if (!isValidCommandName(commandName)) {
    return res.status(400).json({
      success: false,
      message: "Invalid command name.",
    });
  }

  try {
    const docRef = getCommandsRef(channelLogin).doc(commandName);
    const existing = await docRef.get();

    if (!existing.exists) {
      return res.status(404).json({
        success: false,
        message: `Command !${commandName} does not exist.`,
      });
    }

    const updates: Record<string, unknown> = {
      updatedAt: FieldValue.serverTimestamp(),
    };

    const { response, permission, cooldown, enabled } = req.body;

    if (response !== undefined) {
      if (typeof response !== "string" || response.trim().length === 0) {
        return res.status(400).json({
          success: false,
          message: "Response text cannot be empty.",
        });
      }
      if (response.length > MAX_RESPONSE_LENGTH) {
        return res.status(400).json({
          success: false,
          message: `Response must be ${MAX_RESPONSE_LENGTH} characters or fewer.`,
        });
      }
      updates.response = response.trim();
    }

    if (permission !== undefined) {
      if (!VALID_PERMISSIONS.includes(permission)) {
        return res.status(400).json({
          success: false,
          message: `Invalid permission. Must be one of: ${VALID_PERMISSIONS.join(", ")}`,
        });
      }
      updates.permission = permission;
    }

    if (cooldown !== undefined) {
      if (typeof cooldown !== "number") {
        return res.status(400).json({
          success: false,
          message: "Cooldown must be a number.",
        });
      }
      updates.cooldownMs = Math.max(0, Math.min(300000, cooldown));
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

    logger.info("Custom command updated", { channelLogin, commandName });

    res.json({
      success: true,
      message: `Command !${commandName} updated.`,
    });
  } catch (error) {
    logger.error("Error updating custom command", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error updating custom command",
    });
  }
});

// ─── DELETE /api/custom-commands/:name ───────────────────────────────────────
router.delete("/:name", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const commandName = req.params.name?.trim().toLowerCase();

  if (!isValidCommandName(commandName)) {
    return res.status(400).json({
      success: false,
      message: "Invalid command name.",
    });
  }

  try {
    const docRef = getCommandsRef(channelLogin).doc(commandName);
    const existing = await docRef.get();

    if (!existing.exists) {
      return res.status(404).json({
        success: false,
        message: `Command !${commandName} does not exist.`,
      });
    }

    await docRef.delete();

    logger.info("Custom command deleted", { channelLogin, commandName });

    res.json({
      success: true,
      message: `Command !${commandName} deleted.`,
    });
  } catch (error) {
    logger.error("Error deleting custom command", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error deleting custom command",
    });
  }
});

export default router;
