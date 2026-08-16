/**
 * API module
 * Combines all API routers
 */

import { Router } from "express";
import { authenticateApiRequest } from "@/auth/jwt.middleware";
import {
  apiLimiter,
  personaWriteLimiter,
  aiPromptWriteLimiter,
  checkinWriteLimiter,
  requireFirestore,
} from "@/config/middleware";
import botRouter from "./bot.router";
import commandsRouter from "./commands.router";
import autoChatRouter from "./autoChat.router";
import authStatusRouter from "./authStatus.router";
import customCommandsRouter from "./customCommands.router";
import checkinRouter from "./checkin.router";
import timersRouter from "./timers.router";
import personaRouter from "./persona.router";

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
router.use("/custom-commands", aiPromptWriteLimiter, customCommandsRouter);
router.use("/checkin", checkinWriteLimiter, checkinRouter);
router.use("/timers", aiPromptWriteLimiter, timersRouter);
// Routers whose writes run an LLM safety check get a tighter, per-user limit on
// top of apiLimiter. It must sit after authenticateApiRequest so req.user exists.
router.use("/persona", personaWriteLimiter, personaRouter);

export default router;
