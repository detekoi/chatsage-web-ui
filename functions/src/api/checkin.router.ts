/**
 * Check-In router
 * Manages the Daily Check-In Channel Point Reward.
 * Creates/updates/deletes the Twitch reward via Helix API automatically.
 *
 * Firestore structure:
 *   customCommands/{channelName}/checkinConfig/settings
 */

import { Router, Response } from "express";
import axios, { AxiosInstance } from "axios";
import { getDb, FieldValue } from "@/config/database";
import { CUSTOM_COMMANDS_COLLECTION, TWITCH_CLIENT_ID } from "@/config/constants";
import { logger } from "@/config/logger";
import { AuthenticatedRequest } from "@/auth/jwt.middleware";
import { getValidTwitchTokenForUser } from "@/tokens";

const router = Router();

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getCheckinConfigRef(channelName: string) {
    return getDb()
        .collection(CUSTOM_COMMANDS_COLLECTION)
        .doc(channelName)
        .collection("checkinConfig")
        .doc("settings");
}

function createHelixClient(accessToken: string): AxiosInstance {
    return axios.create({
        baseURL: "https://api.twitch.tv/helix",
        headers: {
            "Client-ID": TWITCH_CLIENT_ID,
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
        },
        timeout: 15000,
    });
}

// ─── GET /api/checkin ────────────────────────────────────────────────────────
router.get("/", async (req: AuthenticatedRequest, res: Response) => {
    const channelLogin = req.user.login;
    try {
        const docSnap = await getCheckinConfigRef(channelLogin).get();

        if (!docSnap.exists) {
            return res.json({
                success: true,
                config: {
                    enabled: false,
                    rewardId: null,
                    title: "Daily Check-In",
                    cost: 100,
                    responseTemplate: "$(user) checked in! Day #$(checkin_count) 🎉",
                    useAi: false,
                    aiPrompt: "",
                },
            });
        }

        return res.json({ success: true, config: docSnap.data() });
    } catch (error: any) {
        logger.error("Error fetching check-in config", {
            channel: channelLogin,
            error: error.message,
        });
        return res.status(500).json({
            success: false,
            message: "Failed to load check-in configuration",
        });
    }
});

// ─── PUT /api/checkin ────────────────────────────────────────────────────────
// Creates or updates the Channel Point Reward on Twitch + saves config
router.put("/", async (req: AuthenticatedRequest, res: Response) => {
    const channelLogin = req.user.login;
    const broadcasterId = req.user.userId;
    const log = logger.child({ endpoint: "PUT /api/checkin", channelLogin });

    try {
        const {
            enabled,
            title: rawTitle,
            cost: rawCost,
            responseTemplate,
            useAi,
            aiPrompt,
        } = req.body;

        // Normalize inputs
        const title = (rawTitle || "Daily Check-In").toString().slice(0, 45);
        const cost = Math.max(1, Math.min(999999, parseInt(rawCost || 100, 10)));

        // Validate lengths
        if (responseTemplate && typeof responseTemplate === "string" && responseTemplate.length > 500) {
            return res.status(400).json({ success: false, message: "Response template must be 500 characters or fewer" });
        }
        if (aiPrompt && typeof aiPrompt === "string" && aiPrompt.length > 500) {
            return res.status(400).json({ success: false, message: "AI prompt must be 500 characters or fewer" });
        }

        // Load existing config
        const existingSnap = await getCheckinConfigRef(channelLogin).get();
        const existingConfig = existingSnap.exists ? existingSnap.data() || {} : {};
        let rewardId: string | null = existingConfig.rewardId || null;

        const accessToken = await getValidTwitchTokenForUser(broadcasterId);
        const helix = createHelixClient(accessToken);

        const twitchRewardBody = {
            title,
            cost,
            prompt: "",
            is_user_input_required: false,
            should_redemptions_skip_request_queue: true,
            is_enabled: !!enabled,
            is_max_per_user_per_stream_enabled: true,
            max_per_user_per_stream: 1,
        };

        if (enabled && !rewardId) {
            // Create the reward on Twitch
            try {
                const createResp = await helix.post<{ data: Array<{ id: string }> }>(
                    `/channel_points/custom_rewards?broadcaster_id=${encodeURIComponent(broadcasterId)}`,
                    twitchRewardBody,
                );
                const newReward = createResp.data?.data?.[0];
                if (newReward?.id) {
                    rewardId = newReward.id;
                    log.info("Created Channel Point Reward on Twitch", { rewardId });
                } else {
                    throw new Error("No reward data returned from Twitch");
                }
            } catch (err: any) {
                const errMsg = err?.response?.data?.message || err.message || "";
                const errStatus = err?.response?.status;

                if (errStatus === 403) {
                    return res.status(403).json({
                        success: false,
                        message: "Channel Point Rewards require Twitch Affiliate or Partner status.",
                    });
                }

                // Handle duplicate: a reward with this title already exists
                if (errStatus === 400 && errMsg === "CREATE_CUSTOM_REWARD_DUPLICATE_REWARD") {
                    // Try to find and reuse the existing one
                    try {
                        const listResp = await helix.get<{ data: Array<{ id: string; title: string }> }>(
                            `/channel_points/custom_rewards?broadcaster_id=${encodeURIComponent(broadcasterId)}&only_manageable_rewards=true`,
                        );
                        const existing = listResp.data?.data?.find((r) => r.title === title);
                        if (existing) {
                            rewardId = existing.id;
                            log.info("Reusing existing reward with same title", { rewardId });
                            // Sync settings
                            await helix.patch(
                                `/channel_points/custom_rewards?broadcaster_id=${encodeURIComponent(broadcasterId)}&id=${encodeURIComponent(rewardId)}`,
                                twitchRewardBody,
                            );
                        } else {
                            return res.status(400).json({
                                success: false,
                                message: `A Channel Point Reward named "${title}" already exists but was created outside this app. Please delete it from your Twitch Dashboard and try again.`,
                            });
                        }
                    } catch (listErr: any) {
                        log.error("Failed to list rewards for duplicate resolution", { error: listErr.message });
                        return res.status(500).json({ success: false, message: "Failed to resolve duplicate reward" });
                    }
                } else {
                    log.error("Failed to create reward on Twitch", { status: errStatus, error: errMsg });
                    return res.status(500).json({ success: false, message: `Failed to create reward: ${errMsg}` });
                }
            }
        } else if (rewardId) {
            // Reward exists — sync settings to Twitch
            try {
                await helix.patch(
                    `/channel_points/custom_rewards?broadcaster_id=${encodeURIComponent(broadcasterId)}&id=${encodeURIComponent(rewardId)}`,
                    twitchRewardBody,
                );
                log.info("Updated Channel Point Reward on Twitch", { rewardId });
            } catch (err: any) {
                const errStatus = err?.response?.status;
                if (errStatus === 404 && enabled) {
                    // Reward was deleted externally — recreate
                    log.info("Reward not found on Twitch, recreating");
                    try {
                        const createResp = await helix.post<{ data: Array<{ id: string }> }>(
                            `/channel_points/custom_rewards?broadcaster_id=${encodeURIComponent(broadcasterId)}`,
                            twitchRewardBody,
                        );
                        rewardId = createResp.data?.data?.[0]?.id || null;
                    } catch (createErr: any) {
                        log.error("Failed to recreate reward", { error: createErr.message });
                        return res.status(500).json({ success: false, message: "Failed to recreate reward on Twitch" });
                    }
                } else {
                    log.warn("Failed to update reward on Twitch (non-fatal)", { status: errStatus, error: err.message });
                }
            }
        }

        // Save config in Firestore
        const configData: Record<string, any> = {
            enabled: !!enabled,
            rewardId,
            title,
            cost,
            responseTemplate: responseTemplate || "",
            useAi: !!useAi,
            aiPrompt: aiPrompt || "",
            updatedAt: FieldValue.serverTimestamp(),
        };

        await getCheckinConfigRef(channelLogin).set(configData, { merge: true });
        log.info("Check-in config saved", { enabled, rewardId });

        return res.json({
            success: true,
            config: configData,
            message: enabled ? "Daily Check-In enabled!" : "Check-in settings saved",
        });
    } catch (error: any) {
        log.error("Error in PUT /api/checkin", { error: error.message });

        if (error.message?.includes("re-authenticate") || error.message?.includes("token")) {
            return res.status(401).json({
                success: false,
                message: "Please re-authenticate with Twitch to manage Channel Point Rewards",
                needsReauth: true,
            });
        }

        return res.status(500).json({ success: false, message: "Failed to save check-in configuration" });
    }
});

// ─── DELETE /api/checkin ─────────────────────────────────────────────────────
// Deletes the Channel Point Reward on Twitch + disables in Firestore
router.delete("/", async (req: AuthenticatedRequest, res: Response) => {
    const channelLogin = req.user.login;
    const broadcasterId = req.user.userId;
    const log = logger.child({ endpoint: "DELETE /api/checkin", channelLogin });

    try {
        const docSnap = await getCheckinConfigRef(channelLogin).get();
        const existingConfig = docSnap.exists ? docSnap.data() || {} : {};
        const rewardId = existingConfig.rewardId;

        let twitchDeleted = false;

        if (rewardId) {
            try {
                const accessToken = await getValidTwitchTokenForUser(broadcasterId);
                const helix = createHelixClient(accessToken);
                await helix.delete(
                    `/channel_points/custom_rewards?broadcaster_id=${encodeURIComponent(broadcasterId)}&id=${encodeURIComponent(rewardId)}`,
                );
                twitchDeleted = true;
                log.info("Deleted Channel Point Reward from Twitch", { rewardId });
            } catch (err: any) {
                const status = err?.response?.status;
                // 404 = already deleted on Twitch; treat as success
                if (status === 404) {
                    twitchDeleted = true;
                } else {
                    log.warn("Twitch delete failed (non-fatal)", { status, error: err.message });
                }
            }
        }

        // Disable locally
        await getCheckinConfigRef(channelLogin).set({
            ...existingConfig,
            enabled: false,
            rewardId: twitchDeleted ? null : rewardId,
            updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });

        return res.json({
            success: true,
            twitchDeleted,
            message: twitchDeleted ? "Check-in reward disabled & deleted" : "Check-in disabled locally",
        });
    } catch (error: any) {
        log.error("Error in DELETE /api/checkin", { error: error.message });
        return res.status(500).json({ success: false, message: "Failed to disable check-in" });
    }
});

export default router;
