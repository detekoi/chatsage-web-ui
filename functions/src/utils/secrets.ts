/**
 * Secret Manager utility functions
 * Provides helpers for accessing and managing secrets
 */

import { getSecretManager, getProjectId } from "@/config/database";
import { WEBUI_INTERNAL_TOKEN, ALLOWED_CHANNELS_SECRET_NAME } from "@/config/constants";
import { logger } from "@/config/logger";

// Cache for secrets to reduce Secret Manager API calls
const secretCache = new Map<string, { value: string; expiresAt: number }>();
const SECRET_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Normalizes a secret path to include version
 * @param secretInput - Secret path or name
 * @returns Full secret version path
 */
export function normalizeSecretVersionPath(secretInput: string): string {
  if (!secretInput) {
    throw new Error("secretInput is empty");
  }

  // If already has version, return as-is
  if (secretInput.includes("/versions/")) {
    return secretInput;
  }

  // Add latest version
  return `${secretInput}/versions/latest`;
}

/**
 * Gets a secret value from Secret Manager
 * @param secretPath - Full path to secret version
 * @param useCache - Whether to use caching (default: true)
 * @returns Secret value as string
 */
export async function getSecret(secretPath: string, useCache = true): Promise<string> {
  const normalizedPath = normalizeSecretVersionPath(secretPath);

  // Check cache first
  if (useCache) {
    const cached = secretCache.get(normalizedPath);
    if (cached && cached.expiresAt > Date.now()) {
      logger.debug("Using cached secret", { path: normalizedPath });
      return cached.value;
    }
  }

  try {
    const secretManager = getSecretManager();
    const [version] = await secretManager.accessSecretVersion({ name: normalizedPath });
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

    // Cache the value
    if (useCache && value) {
      secretCache.set(normalizedPath, {
        value,
        expiresAt: Date.now() + SECRET_CACHE_TTL_MS,
      });
    }

    return value;
  } catch (error: any) {
    logger.error("Error fetching secret from Secret Manager", {
      path: normalizedPath,
      error: error.message,
    });
    throw new Error(`Failed to fetch secret: ${error.message}`);
  }
}

/**
 * Gets the internal bot token from Secret Manager
 * @returns Internal bot token value
 */
export async function getInternalBotTokenValue(): Promise<string> {
  if (!WEBUI_INTERNAL_TOKEN) {
    throw new Error("WEBUI_INTERNAL_TOKEN is not configured (expected Secret Manager path)");
  }

  try {
    return await getSecret(WEBUI_INTERNAL_TOKEN);
  } catch (error: any) {
    logger.error("Error fetching WEBUI_INTERNAL_TOKEN", { error: error.message });
    throw new Error("Failed to fetch internal bot token");
  }
}

/**
 * Gets the list of allowed channels from Secret Manager
 * @returns Array of allowed channel login names
 */
export async function getAllowedChannelsList(): Promise<string[]> {
  try {
    if (!ALLOWED_CHANNELS_SECRET_NAME) {
      logger.error("ALLOWED_CHANNELS_SECRET_NAME is not set. Denying all by default");
      return [];
    }

    const csvData = await getSecret(ALLOWED_CHANNELS_SECRET_NAME);

    if (!csvData.trim()) {
      logger.warn("Allowed channels secret is empty. Denying all by default");
      return [];
    }

    const channels = csvData
      .split(",")
      .map((ch) => ch.trim().toLowerCase())
      .filter(Boolean);

    logger.info(`Loaded ${channels.length} allowed channels from Secret Manager`);
    return channels;
  } catch (error: any) {
    logger.error("Error fetching allowed channels from Secret Manager", {
      error: error.message,
    });
    return [];
  }
}

/**
 * Creates or updates a secret in Secret Manager
 * @param secretId - Secret ID (without project prefix)
 * @param value - Secret value to store
 * @returns Full path to the new secret version
 */
export async function createOrUpdateSecret(secretId: string, value: string): Promise<string> {
  const secretManager = getSecretManager();
  const projectId = getProjectId();
  const secretName = `projects/${projectId}/secrets/${secretId}`;

  try {
    // Try to get existing secret
    await secretManager.getSecret({ name: secretName });
    logger.debug("Secret already exists, adding new version", { secretId });
  } catch (err: any) {
    // Secret doesn't exist, create it
    if (err.code === 5) { // NOT_FOUND
      logger.info("Creating new secret", { secretId });
      await secretManager.createSecret({
        parent: `projects/${projectId}`,
        secretId,
        secret: { replication: { automatic: {} } },
      });
    } else {
      throw err;
    }
  }

  // Add new version
  const valueBytes = Buffer.from(value, "utf8");
  const [version] = await secretManager.addSecretVersion({
    parent: secretName,
    payload: { data: valueBytes },
  });

  logger.info("Added new secret version", {
    secretId,
    versionPath: version.name,
  });

  return version.name || "";
}

/**
 * Clears the secret cache
 * Useful for testing or forcing refresh
 */
export function clearSecretCache() {
  secretCache.clear();
  logger.debug("Secret cache cleared");
}
