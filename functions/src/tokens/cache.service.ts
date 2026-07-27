/**
 * Token cache service
 * Firestore-backed caching of access tokens, shared across all instances.
 *
 * SECURITY: this cache deliberately does NOT live in process memory. Cloud
 * Functions runs an unbounded number of concurrent instances, and a per-process
 * Map cannot be invalidated fleet-wide — revoking a user's token would clear it
 * only on the instance that happened to serve the revocation request, while
 * every other warm instance kept handing out the revoked token until it expired
 * on its own (up to `expiresIn - TOKEN_CACHE_BUFFER_SECONDS`). Storing the
 * cache in Firestore makes clearCachedToken() take effect everywhere at once.
 *
 * The token is kept in the same document as the refresh token
 * (users/{twitchUserId}/private/oauth), which already holds strictly
 * longer-lived credential material, so this adds no new exposure surface.
 * Client access to Firestore is denied outright by firestore.rules.
 */

import { getDb, FieldValue } from "@/config/database";
import { logger } from "@/config/logger";
import { TOKEN_CACHE_BUFFER_SECONDS } from "@/config/constants";
import { getOauthDocRef } from "./firestoreRefreshToken.service";

/**
 * Gets a cached token for a user if still valid
 * @param userId - Twitch broadcaster user ID
 * @returns Cached token, or null if absent, expired, or unreadable
 */
export async function getCachedToken(userId: string): Promise<string | null> {
  try {
    const snapshot = await getOauthDocRef(getDb(), userId).get();
    const data = snapshot.data();

    const token = data?.cachedAccessToken;
    const expiresAt = data?.accessTokenExpiresAt;

    if (typeof token !== "string" || !token || typeof expiresAt !== "number") {
      return null;
    }

    if (expiresAt <= Date.now()) {
      logger.debug("Cached token expired", { userId });
      return null;
    }

    logger.debug("Using cached token", {
      userId,
      expiresInSeconds: Math.floor((expiresAt - Date.now()) / 1000),
    });
    return token;
  } catch (error: unknown) {
    // Fail open: a cache read failure must not break the request. The caller
    // falls through to a refresh, which is correct, just slower.
    logger.warn("Failed to read cached token, falling back to refresh", {
      userId,
      error: (error as Error).message,
    });
    return null;
  }
}

/**
 * Caches an access token for a user
 * @param userId - Twitch broadcaster user ID
 * @param token - Access token to cache
 * @param expiresIn - Token expiration in seconds
 */
export async function cacheToken(
  userId: string,
  token: string,
  expiresIn: number,
): Promise<void> {
  // Calculate expiration with buffer (5 minutes before actual expiry)
  const expiresAt = Date.now() + ((expiresIn - TOKEN_CACHE_BUFFER_SECONDS) * 1000);

  try {
    await getOauthDocRef(getDb(), userId).set(
      {
        cachedAccessToken: token,
        accessTokenExpiresAt: expiresAt,
        accessTokenCachedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    // SECURITY: never log token content
    logger.debug("Cached access token", {
      userId,
      expiresInSeconds: expiresIn - TOKEN_CACHE_BUFFER_SECONDS,
    });
  } catch (error: unknown) {
    // Non-fatal: the caller already holds a usable token for this request.
    logger.warn("Failed to cache access token", {
      userId,
      error: (error as Error).message,
    });
  }
}

/**
 * Clears the cached token for a user across every instance.
 *
 * @param userId - Twitch broadcaster user ID
 * @returns True if the cache was cleared; false if the write failed and a
 *          revoked token may still be served until it expires naturally.
 */
export async function clearCachedToken(userId: string): Promise<boolean> {
  try {
    await getOauthDocRef(getDb(), userId).set(
      {
        cachedAccessToken: FieldValue.delete(),
        accessTokenExpiresAt: FieldValue.delete(),
        accessTokenClearedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    logger.debug("Cleared cached token", { userId });
    return true;
  } catch (error: unknown) {
    logger.error("Failed to clear cached access token", {
      userId,
      error: (error as Error).message,
    });
    return false;
  }
}
