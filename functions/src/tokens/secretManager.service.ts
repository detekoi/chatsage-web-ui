/**
 * Secret Manager service for refresh tokens
 * Handles storage and rotation of Twitch refresh tokens
 *
 * SECURITY: This fixes the critical bug where refresh tokens weren't being rotated properly
 */

import { getSecretManager, getProjectId } from "@/config/database";
import { logger } from "@/config/logger";

/**
 * Gets a refresh token from Secret Manager
 * @param secretPath - Full path to secret version
 * @returns Refresh token value
 */
export async function getRefreshToken(secretPath: string): Promise<string> {
  try {
    const secretManager = getSecretManager();
    const [version] = await secretManager.accessSecretVersion({ name: secretPath });

    const payloadData = version.payload?.data;
    let value = "";

    if (payloadData) {
      if (typeof payloadData === "string") {
        value = payloadData;
      } else if (Buffer.isBuffer(payloadData)) {
        value = payloadData.toString("utf8");
      } else if (payloadData instanceof Uint8Array) {
        value = Buffer.from(payloadData).toString("utf8");
      }
    }

    if (!value) {
      throw new Error("Refresh token is empty");
    }

    // SECURITY: Never log token content
    logger.debug("Retrieved refresh token from Secret Manager", {
      secretPath: secretPath.split("/versions/")[0], // Log secret name without version
      hasValue: !!value,
      valueLength: value.length,
    });

    return value;
  } catch (error: unknown) {
    const err = error as Error;
    logger.error("Error fetching refresh token from Secret Manager", {
      secretPath: secretPath.split("/versions/")[0],
      error: err.message,
    });
    throw new Error(`Failed to fetch refresh token: ${err.message}`);
  }
}

/**
 * Stores or rotates a refresh token in Secret Manager
 * Creates the secret if it doesn't exist, or adds a new version
 *
 * @param userId - Twitch user ID
 * @param refreshToken - The refresh token to store
 * @returns Full path to the new secret version
 */
export async function storeRefreshToken(userId: string, refreshToken: string): Promise<string> {
  try {
    const secretManager = getSecretManager();
    const projectId = getProjectId();
    const secretId = `twitch-refresh-token-${userId}`;
    const secretName = `projects/${projectId}/secrets/${secretId}`;

    // Try to get existing secret
    try {
      await secretManager.getSecret({ name: secretName });
      logger.debug("Secret already exists, adding new version", { secretId });
    } catch (err: unknown) {
      const error = err as { code?: number };
      // Secret doesn't exist (code 5 = NOT_FOUND), create it
      if (error.code === 5) {
        logger.info("Creating new secret for user", { userId, secretId });
        await secretManager.createSecret({
          parent: `projects/${projectId}`,
          secretId,
          secret: { replication: { automatic: {} } },
        });
      } else {
        throw err;
      }
    }

    // Add new version (this rotates the token)
    const tokenBytes = Buffer.from(refreshToken, "utf8");

    // SECURITY: Never log token content
    logger.debug("Adding secret version", {
      secretId,
      tokenLength: refreshToken.length,
    });

    const [version] = await secretManager.addSecretVersion({
      parent: secretName,
      payload: { data: tokenBytes },
    });

    const versionName = version.name || "";

    logger.info("Stored refresh token in Secret Manager", {
      userId,
      secretId,
      versionPath: versionName,
    });

    return versionName;
  } catch (error: unknown) {
    const err = error as Error;
    logger.error("Error storing refresh token", {
      userId,
      error: err.message,
    });
    throw new Error(`Failed to store refresh token: ${err.message}`);
  }
}

/**
 * Rotates a refresh token after it's been used
 * This is critical because Twitch rotates refresh tokens on every use
 *
 * @param userId - Twitch user ID
 * @param newRefreshToken - The new refresh token from Twitch
 * @param oldSecretPath - Path to the old secret version
 * @returns Path to the new secret version
 */
export async function rotateRefreshToken(
  userId: string,
  newRefreshToken: string,
  oldSecretPath: string,
): Promise<string> {
  // SECURITY: Never log token content, only metadata
  logger.info("Rotating refresh token", {
    userId,
    oldSecretPath: oldSecretPath.split("/versions/")[0],
    newTokenLength: newRefreshToken.length,
  });

  // Store the new token (this creates a new version)
  const newSecretPath = await storeRefreshToken(userId, newRefreshToken);

  logger.info("Refresh token rotated successfully", {
    userId,
    newSecretPath: newSecretPath.split("/versions/")[0],
  });

  return newSecretPath;
}
