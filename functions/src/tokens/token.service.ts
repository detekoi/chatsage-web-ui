/**
 * Main token service
 * Orchestrates token caching, refresh, and Secret Manager operations
 */

import { getDb, FieldValue } from "@/config/database";
import { CHANNELS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";
import { getCachedToken, cacheToken, clearCachedToken } from "./cache.service";
import { refreshTwitchToken } from "./refresh.service";
import { getRefreshToken, rotateRefreshToken } from "./secretManager.service";
import { AuthError } from "@/utils/errors";

/**
 * Gets a valid Twitch access token for a user
 * Uses cache if available, otherwise refreshes from Twitch
 *
 * @param userLogin - User login name
 * @returns Valid access token
 * @throws AuthError if unable to get valid token
 */
export async function getValidTwitchTokenForUser(userLogin: string): Promise<string> {
  const db = getDb();

  // Step 1: Check cache first
  const cachedToken = getCachedToken(userLogin);
  if (cachedToken) {
    return cachedToken;
  }

  logger.debug("No cached token, fetching from Firestore", { userLogin });

  // Step 2: Get refresh token path from Firestore
  const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userLogin);
  const userDoc = await userDocRef.get();

  if (!userDoc.exists) {
    logger.warn("User document not found", { userLogin });
    throw new AuthError("User not found or not authenticated with Twitch", 404);
  }

  const userData = userDoc.data();
  const { refreshTokenSecretPath, twitchUserId } = userData || {};

  if (!refreshTokenSecretPath) {
    logger.warn("No refresh token secret path found", { userLogin });
    throw new AuthError("Refresh token not available. User needs to re-authenticate", 401);
  }

  // Step 3: Get refresh token from Secret Manager
  logger.debug("Fetching refresh token from Secret Manager", {
    userLogin,
    secretPath: refreshTokenSecretPath.split("/versions/")[0],
  });

  try {
    const currentRefreshToken = await getRefreshToken(refreshTokenSecretPath);

    // Step 4: Refresh the access token
    logger.info("Refreshing access token", { userLogin });
    const newTokens = await refreshTwitchToken(currentRefreshToken);

    // Step 5: Handle refresh token rotation
    // CRITICAL: Twitch rotates refresh tokens on every use
    if (newTokens.refreshToken && newTokens.refreshToken !== currentRefreshToken) {
      logger.info("Refresh token rotated by Twitch", {
        userLogin,
        oldTokenLength: currentRefreshToken.length,
        newTokenLength: newTokens.refreshToken.length,
      });

      try {
        // Store the new refresh token
        const newSecretPath = await rotateRefreshToken(
          twitchUserId,
          newTokens.refreshToken,
          refreshTokenSecretPath,
        );

        // Update Firestore with new secret path
        await userDocRef.update({
          refreshTokenSecretPath: newSecretPath,
          lastTokenRefreshAt: FieldValue.serverTimestamp(),
          needsTwitchReAuth: false,
          lastTokenError: null,
          lastTokenErrorAt: null,
        });

        logger.info("Firestore updated with new refresh token path", {
          userLogin,
          newSecretPath: newSecretPath.split("/versions/")[0],
        });
      } catch (secretError: unknown) {
        const err = secretError as Error;
        logger.error("CRITICAL: Failed to save rotated refresh token", {
          userLogin,
          error: err.message,
        });
        // Don't throw - we still have a valid access token for this request
        // But log prominently since next refresh will fail
      }
    } else if (!newTokens.refreshToken) {
      logger.warn("Twitch did not return a new refresh token (unexpected)", {
        userLogin,
      });
      await userDocRef.update({
        lastTokenRefreshAt: FieldValue.serverTimestamp(),
        needsTwitchReAuth: false,
      });
    } else {
      logger.debug("Refresh token unchanged (reusing same token)", {
        userLogin,
      });
      await userDocRef.update({
        lastTokenRefreshAt: FieldValue.serverTimestamp(),
        needsTwitchReAuth: false,
      });
    }

    // Step 6: Cache the new access token
    cacheToken(userLogin, newTokens.accessToken, newTokens.expiresIn);

    logger.info("Successfully obtained valid access token", {
      userLogin,
      expiresIn: newTokens.expiresIn,
    });

    return newTokens.accessToken;
  } catch (error: unknown) {
    const err = error as Error;
    logger.error("Failed to get valid token", {
      userLogin,
      error: err.message,
    });

    // Clear cache on error
    clearCachedToken(userLogin);

    // Mark user as needing re-auth in Firestore
    try {
      await userDocRef.update({
        needsTwitchReAuth: true,
        lastTokenError: err.message,
        lastTokenErrorAt: FieldValue.serverTimestamp(),
      });
      logger.debug("Marked user as needing re-auth", { userLogin });
    } catch (updateError: unknown) {
      const updateErr = updateError as Error;
      logger.error("Failed to update user document", {
        userLogin,
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
 * @param userLogin - User login name
 * @param reason - Reason for clearing tokens (for logging)
 * @returns True if successful
 */
export async function clearUserTokens(
  userLogin: string,
  reason = "Manual token clear",
): Promise<boolean> {
  const db = getDb();

  if (!userLogin) {
    logger.error("No userLogin provided to clearUserTokens");
    return false;
  }

  try {
    // Clear from cache
    clearCachedToken(userLogin);

    // Update Firestore
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userLogin);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      logger.warn("User document not found when clearing tokens", { userLogin });
      return false;
    }

    await userDocRef.update({
      needsTwitchReAuth: true,
      lastTokenClearReason: reason,
      lastTokenClearAt: FieldValue.serverTimestamp(),
    });

    logger.info("Cleared user tokens", { userLogin, reason });
    return true;
  } catch (error: unknown) {
    const err = error as Error;
    logger.error("Failed to clear user tokens", {
      userLogin,
      error: err.message,
    });
    return false;
  }
}
