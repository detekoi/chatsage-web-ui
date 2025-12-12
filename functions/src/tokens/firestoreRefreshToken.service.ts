/**
 * Firestore-backed per-user OAuth token storage.
 *
 * Stores Twitch refresh tokens at:
 *   users/{twitchUserId}/private/oauth
 *
 * NOTE: This replaces the per-user Secret Manager token storage to reduce cost.
 */

import type { Firestore } from "@google-cloud/firestore";
import { FieldValue } from "@/config/database";
import { logger } from "@/config/logger";

const USERS_COLLECTION = "users";
const PRIVATE_SUBCOLLECTION = "private";
const OAUTH_DOC_ID = "oauth";

function getOauthDocRef(db: Firestore, twitchUserId: string) {
  return db
    .collection(USERS_COLLECTION)
    .doc(twitchUserId)
    .collection(PRIVATE_SUBCOLLECTION)
    .doc(OAUTH_DOC_ID);
}

export async function getStoredTwitchRefreshToken(
  db: Firestore,
  twitchUserId: string,
): Promise<string | null> {
  const doc = await getOauthDocRef(db, twitchUserId).get();
  const token = doc.data()?.twitchRefreshToken;

  if (!token || typeof token !== "string") {
    return null;
  }

  return token;
}

export async function storeTwitchRefreshToken(
  db: Firestore,
  twitchUserId: string,
  refreshToken: string,
  metadata: { migratedFrom?: string; reason?: string } = {},
): Promise<void> {
  // SECURITY: Never log token content
  logger.info("Storing Twitch refresh token in Firestore", {
    twitchUserId,
    tokenLength: refreshToken.length,
    ...metadata,
  });

  await getOauthDocRef(db, twitchUserId).set(
    {
      twitchRefreshToken: refreshToken,
      updatedAt: FieldValue.serverTimestamp(),
      ...(metadata.migratedFrom ? { migratedFrom: metadata.migratedFrom } : {}),
      ...(metadata.reason ? { updateReason: metadata.reason } : {}),
    },
    { merge: true },
  );
}


