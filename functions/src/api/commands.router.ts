/**
 * Commands router
 * Endpoints for managing bot commands
 */

import { Router, Response } from "express";
import { getDb, FieldValue } from "@/config/database";
import { ALL_COMMANDS, CHANNEL_COMMANDS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { validateBoolean } from "@/utils/validation";

const router = Router();

/**
 * GET /api/commands
 * Get command settings for the authenticated user's channel
 */
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const db = getDb();

  try {
    const docRef = db.collection(CHANNEL_COMMANDS_COLLECTION).doc(channelLogin);
    const snap = await docRef.get();
    const data = snap.exists ? snap.data() : {};
    const disabledCommands = data?.disabledCommands || [];

    const commandSettings = ALL_COMMANDS.map((cmd) => ({
      primaryName: cmd,
      name: cmd,
      enabled: !disabledCommands.includes(cmd),
    }));

    res.json({
      success: true,
      commands: commandSettings,
    });
  } catch (error) {
    logger.error("Error fetching command settings", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error fetching command settings",
    });
  }
});

/**
 * POST /api/commands
 * Update a command's enabled/disabled status
 */
router.post("/", async (req: AuthenticatedRequest, res: Response) => {
  const channelLogin = req.user.login;
  const db = getDb();

  try {
    const { command, enabled } = req.body;

    if (!command || typeof command !== "string") {
      return res.status(400).json({
        success: false,
        message: "Invalid command name",
      });
    }

    // Validate enabled is a boolean
    try {
      validateBoolean(enabled);
    } catch {
      return res.status(400).json({
        success: false,
        message: "Invalid enabled value - must be boolean",
      });
    }

    const docRef = db.collection(CHANNEL_COMMANDS_COLLECTION).doc(channelLogin);

    // Use array operations to match bot's expected structure
    if (enabled) {
      // Enable command by removing from disabledCommands array
      await docRef.set(
        {
          disabledCommands: FieldValue.arrayRemove(command),
          channelName: channelLogin,
        },
        { merge: true },
      );

      logger.info("Enabled command", {
        channelLogin,
        command,
      });
    } else {
      // Disable command by adding to disabledCommands array
      await docRef.set(
        {
          disabledCommands: FieldValue.arrayUnion(command),
          channelName: channelLogin,
        },
        { merge: true },
      );

      logger.info("Disabled command", {
        channelLogin,
        command,
      });
    }

    res.json({
      success: true,
      message: `Command ${command} ${enabled ? "enabled" : "disabled"} successfully.`,
    });
  } catch (error) {
    logger.error("Error updating command settings", {
      channelLogin,
      error: (error as Error).message,
    });
    res.status(500).json({
      success: false,
      message: "Error updating command settings",
    });
  }
});

export default router;
