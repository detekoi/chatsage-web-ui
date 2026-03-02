/**
 * Main token service
 * Orchestrates token caching, refresh, and Secret Manager operations
 */

import { getDb, FieldValue } from "@/config/database";
import { CHANNELS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { getCachedToken, cacheToken, clearCachedToken } from "./cache.service";
import { refreshTwitchToken } from "./refresh.service";
import { getStoredTwitchRefreshToken, storeTwitchRefreshToken } from "./firestoreRefreshToken.service";
import { AuthError } from "@/utils/errors";

/**
 * Gets a valid Twitch access token for a user
 * Uses cache if available, otherwise refreshes from Twitch
 *
 * @param userId - Twitch broadcaster user ID
 * @returns Valid access token
 * @throws AuthError if unable to get valid token
 */
export async function getValidTwitchTokenForUser(userId: string): Promise<string> {
  const db = getDb();

  // Step 1: Check cache first
  const cachedToken = getCachedToken(userId);
  if (cachedToken) {
    return cachedToken;
  }

  logger.debug("No cached token, fetching from Firestore", { userId });

  // Step 2: Get user document from Firestore (keyed by userId)
  const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userId);
  const userDoc = await userDocRef.get();

  if (!userDoc.exists) {
    logger.warn("User document not found", { userId });
    throw new AuthError("User not found or not authenticated with Twitch", 404);
  }

  const twitchUserId = userId;

  try {
    // Step 3: Get refresh token from Firestore (users/{twitchUserId}/private/oauth)
    logger.debug("Fetching refresh token from Firestore", { userId, twitchUserId });

    const currentRefreshToken = await getStoredTwitchRefreshToken(db, twitchUserId);
    if (!currentRefreshToken) {
      logger.warn("No refresh token found in Firestore; user must re-auth", { userId, twitchUserId });
      throw new AuthError("Refresh token not available. User needs to re-authenticate", 401);
    }

    // Step 4: Refresh the access token
    logger.info("Refreshing access token", { userId });
    const newTokens = await refreshTwitchToken(currentRefreshToken);

    // Step 5: Handle refresh token rotation
    // CRITICAL: Twitch rotates refresh tokens on every use
    if (newTokens.refreshToken && newTokens.refreshToken !== currentRefreshToken) {
      logger.info("Refresh token rotated by Twitch", {
        userId,
        oldTokenLength: currentRefreshToken.length,
        newTokenLength: newTokens.refreshToken.length,
      });

      try {
        // Store the new refresh token in Firestore
        await storeTwitchRefreshToken(db, twitchUserId, newTokens.refreshToken, {
          reason: "twitch-rotation",
        });

        // Update managedChannels metadata
        await userDocRef.update({
          lastTokenRefreshAt: FieldValue.serverTimestamp(),
          needsTwitchReAuth: false,
          lastTokenError: null,
          lastTokenErrorAt: null,
        });

        logger.info("Firestore updated with rotated refresh token", { userId, twitchUserId });
      } catch (tokenStoreError: unknown) {
        const err = tokenStoreError as Error;
        logger.error("CRITICAL: Failed to save rotated refresh token to Firestore", {
          userId,
          twitchUserId,
          error: err.message,
        });
        // Don't throw - we still have a valid access token for this request
        // But log prominently since next refresh will fail
      }
    } else if (!newTokens.refreshToken) {
      logger.warn("Twitch did not return a new refresh token (unexpected)", {
        userId,
      });
      await userDocRef.update({
        lastTokenRefreshAt: FieldValue.serverTimestamp(),
        needsTwitchReAuth: false,
      });
    } else {
      logger.debug("Refresh token unchanged (reusing same token)", {
        userId,
      });
      await userDocRef.update({
        lastTokenRefreshAt: FieldValue.serverTimestamp(),
        needsTwitchReAuth: false,
      });
    }

    // Step 6: Cache the new access token
    cacheToken(userId, newTokens.accessToken, newTokens.expiresIn);

    logger.info("Successfully obtained valid access token", {
      userId,
      expiresIn: newTokens.expiresIn,
    });

    return newTokens.accessToken;
  } catch (error: unknown) {
    const err = error as Error;
    logger.error("Failed to get valid token", {
      userId,
      error: err.message,
    });

    // Clear cache on error
    clearCachedToken(userId);

    // Mark user as needing re-auth in Firestore
    try {
      await userDocRef.update({
        needsTwitchReAuth: true,
        lastTokenError: err.message,
        lastTokenErrorAt: FieldValue.serverTimestamp(),
      });
      logger.debug("Marked user as needing re-auth", { userId });
    } catch (updateError: unknown) {
      const updateErr = updateError as Error;
      logger.error("Failed to update user document", {
        userId,
        error: updateErr.message,
      });
    }

    throw new AuthError(
      "Failed to obtain a valid Twitch token. User may need to re-authenticate",
      401,
    );
  }
}

/**
 * Clears cached tokens for a user and marks them for re-auth
 * Useful when forcing a user to re-authenticate
 *
 * @param userId - Twitch broadcaster user ID
 * @param reason - Reason for clearing tokens (for logging)
 * @returns True if successful
 */
export async function clearUserTokens(
  userId: string,
  reason = "Manual token clear",
): Promise<boolean> {
  const db = getDb();

  if (!userId) {
    logger.error("No userId provided to clearUserTokens");
    return false;
  }

  try {
    // Clear from cache
    clearCachedToken(userId);

    // Update Firestore
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userId);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      logger.warn("User document not found when clearing tokens", { userId });
      return false;
    }

    await userDocRef.update({
      needsTwitchReAuth: true,
      lastTokenClearReason: reason,
      lastTokenClearAt: FieldValue.serverTimestamp(),
    });

    logger.info("Cleared user tokens", { userId, reason });
    return true;
  } catch (error: unknown) {
    const err = error as Error;
    logger.error("Failed to clear user tokens", {
      userId,
      error: err.message,
    });
    return false;
  }
}
