/**
 * Database initialization
 * Firestore and Secret Manager client setup
 */

import { Firestore, FieldValue } from "@google-cloud/firestore";
import { SecretManagerServiceClient } from "@google-cloud/secret-manager";
import { logger } from "./logger";

let db: Firestore | null = null;
let secretManagerClient: SecretManagerServiceClient | null = null;

/**
 * Initialize Firestore and Secret Manager clients
 */
export function initializeDatabase() {
  try {
    db = new Firestore();
    secretManagerClient = new SecretManagerServiceClient();
    logger.info("Firestore and Secret Manager initialized successfully");
  } catch (initError: any) {
    logger.error("Failed to initialize Firestore or Secret Manager", {
      error: initError.message,
      stack: initError.stack,
    });
    throw initError;
  }
}

/**
 * Get Firestore instance
 * @throws Error if Firestore is not initialized
 */
export function getDb(): Firestore {
  if (!db) {
    throw new Error("Firestore not initialized. Call initializeDatabase() first.");
  }
  return db;
}

/**
 * Get Secret Manager client
 * @throws Error if Secret Manager is not initialized
 */
export function getSecretManager(): SecretManagerServiceClient {
  if (!secretManagerClient) {
    throw new Error("Secret Manager not initialized. Call initializeDatabase() first.");
  }
  return secretManagerClient;
}

/**
 * Get GCP project ID from environment
 * @throws Error if project ID is not found
 */
export function getProjectId(): string {
  const projectId =
    process.env.GCLOUD_PROJECT ||
    process.env.GCP_PROJECT ||
    process.env.GOOGLE_CLOUD_PROJECT;

  if (!projectId) {
    throw new Error("GCP project ID not found in environment variables");
  }

  return projectId;
}

// Export FieldValue for convenience
export { FieldValue };
