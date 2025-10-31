/**
 * Internal module
 * Internal API endpoints for bot service
 */

import { Router } from "express";
import { authenticateInternalRequest } from "./authentication.middleware";
import { requireFirestore, apiLimiter } from "@/config/middleware";
import adsRouter from "./ads.router";
import eventsubRouter from "./eventsub.router";
import commandsRouter from "./commands.router";

const router = Router();

// Apply middleware to all internal routes
router.use(apiLimiter);
router.use(requireFirestore);
router.use(authenticateInternalRequest);

// Mount routers
router.use("/ads", adsRouter);
router.use("/eventsub", eventsubRouter);
router.use("/commands", commandsRouter);

export default router;
