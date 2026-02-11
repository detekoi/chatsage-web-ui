/**
 * API module
 * Combines all API routers
 */

import { Router } from "express";
import { authenticateApiRequest } from "@/auth/jwt.middleware";
import { apiLimiter, requireFirestore } from "@/config/middleware";
import botRouter from "./bot.router";
import commandsRouter from "./commands.router";
import autoChatRouter from "./autoChat.router";
import authStatusRouter from "./authStatus.router";
import customCommandsRouter from "./customCommands.router";

const router = Router();

// Apply middleware to all API routes
router.use(apiLimiter);
router.use(requireFirestore);
router.use(authenticateApiRequest);

// Mount routers
router.use("/bot", botRouter);
router.use("/commands", commandsRouter);
router.use("/auto-chat", autoChatRouter);
router.use("/auth", authStatusRouter);
router.use("/custom-commands", customCommandsRouter);

export default router;
