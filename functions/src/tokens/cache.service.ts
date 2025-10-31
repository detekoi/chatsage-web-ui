/**
 * Token cache service
 * In-memory caching of access tokens to reduce Twitch API calls
 */

import { logger } from "@/config/logger";
import { TOKEN_CACHE_BUFFER_SECONDS } from "@/config/constants";

interface CachedToken {
  token: string;
  expiresAt: number;
}

// In-memory token cache: userLogin -> { token, expiresAt }
const tokenCache = new Map<string, CachedToken>();

/**
 * Gets a cached token for a user if still valid
 * @param userLogin - User login name
 * @returns Cached token or null if not found or expired
 */
export function getCachedToken(userLogin: string): string | null {
  const cached = tokenCache.get(userLogin);

  if (!cached) {
    return null;
  }

  // Check if token is still valid (with buffer)
  if (cached.expiresAt > Date.now()) {
    const remainingSeconds = Math.floor((cached.expiresAt - Date.now()) / 1000);
    logger.debug("Using cached token", {
      userLogin,
      expiresInSeconds: remainingSeconds,
    });
    return cached.token;
  }

  // Token expired, remove from cache
  logger.debug("Cached token expired", { userLogin });
  tokenCache.delete(userLogin);
  return null;
}

/**
 * Caches an access token for a user
 * @param userLogin - User login name
 * @param token - Access token to cache
 * @param expiresIn - Token expiration in seconds
 */
export function cacheToken(userLogin: string, token: string, expiresIn: number): void {
  // Calculate expiration with buffer (5 minutes before actual expiry)
  const expiresAt = Date.now() + ((expiresIn - TOKEN_CACHE_BUFFER_SECONDS) * 1000);

  tokenCache.set(userLogin, {
    token,
    expiresAt,
  });

  logger.debug("Cached access token", {
    userLogin,
    expiresInSeconds: expiresIn - TOKEN_CACHE_BUFFER_SECONDS,
  });
}

/**
 * Clears a cached token for a user
 * @param userLogin - User login name
 */
export function clearCachedToken(userLogin: string): void {
  const existed = tokenCache.delete(userLogin);
  if (existed) {
    logger.debug("Cleared cached token", { userLogin });
  }
}

/**
 * Clears all cached tokens
 * Useful for testing or maintenance
 */
export function clearAllCachedTokens(): void {
  const count = tokenCache.size;
  tokenCache.clear();
  logger.info("Cleared all cached tokens", { count });
}

/**
 * Gets cache statistics
 * @returns Cache size and entries
 */
export function getCacheStats() {
  return {
    size: tokenCache.size,
    entries: Array.from(tokenCache.keys()),
  };
}
