import { initializeApp } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import axios from "axios";
// Register module alias manually for standalone script execution
import moduleAlias from "module-alias";
import * as path from "path";
moduleAlias.addAlias("@", path.join(__dirname, "../lib/src"));

import { getAppAccessToken } from "@/twitch/appToken.service";
import { TWITCH_CLIENT_ID, TWITCH_HELIX_URL, CHANNELS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";

async function runReconciliation() {
  logger.info("Starting EventSub Reconciliation Sweep...");
  
  // Initialize Firebase (assumes GOOGLE_APPLICATION_CREDENTIALS or default ADC is set)
  initializeApp();
  const db = getFirestore();

  try {
    // 1. Get all active channels from Firestore
    logger.info(`Fetching active channels from ${CHANNELS_COLLECTION}...`);
    const channelsSnapshot = await db.collection(CHANNELS_COLLECTION).get();
    
    const activeBroadcasterIds = new Set<string>();
    let pendingTeardownDocs: FirebaseFirestore.QueryDocumentSnapshot[] = [];

    channelsSnapshot.forEach((doc) => {
      const data = doc.data();
      const broadcasterId = data.twitchUserId || doc.id; // Fallback to doc ID
      
      if (data.isActive) {
        activeBroadcasterIds.add(String(broadcasterId));
      }
      
      if (data.eventsubTeardownPending === true) {
        pendingTeardownDocs.push(doc);
      }
    });

    logger.info(`Found ${activeBroadcasterIds.size} active channels.`);
    logger.info(`Found ${pendingTeardownDocs.length} channels with teardown pending flags.`);

    // 2. Fetch all EventSub subscriptions from Twitch (Paginated)
    logger.info("Fetching all EventSub subscriptions from Twitch...");
    const appAccessToken = await getAppAccessToken();
    const headers = {
      Authorization: `Bearer ${appAccessToken}`,
      "Client-ID": TWITCH_CLIENT_ID,
      "Content-Type": "application/json",
    };

    const subscriptions: { id: string; type: string; condition: any }[] = [];
    let cursor: string | undefined;

    do {
      const list = await axios.get(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, {
        headers,
        params: cursor ? { after: cursor } : {},
      });

      subscriptions.push(...(list.data?.data || []));
      cursor = list.data?.pagination?.cursor;
    } while (cursor);

    logger.info(`Total EventSub subscriptions found on Twitch: ${subscriptions.length}`);

    // 3. Reconcile: Delete subscriptions not belonging to active channels
    let deletedCount = 0;
    let failedCount = 0;
    let keepCount = 0;

    for (const sub of subscriptions) {
      const broadcasterId = String(sub.condition?.broadcaster_user_id);
      
      if (!broadcasterId) {
        logger.warn(`Subscription ${sub.id} of type ${sub.type} has no broadcaster_user_id in condition. Skipping.`);
        continue;
      }

      if (activeBroadcasterIds.has(broadcasterId)) {
        keepCount++;
        continue; // It's an active channel, keep the subscription
      }

      // Found an orphaned subscription!
      logger.info(`Orphaned subscription found! Type: ${sub.type}, Broadcaster: ${broadcasterId}. Deleting...`);
      try {
        await axios.delete(`${TWITCH_HELIX_URL}/eventsub/subscriptions`, {
          headers,
          params: { id: sub.id },
        });
        deletedCount++;
      } catch (err: any) {
        if (err.response?.status === 404) {
          deletedCount++;
        } else {
          failedCount++;
          logger.error(`Failed to delete subscription ${sub.id}: ${err.message}`);
        }
      }
    }

    // 4. Clear pending teardown flags in Firestore
    for (const doc of pendingTeardownDocs) {
        await doc.ref.update({
            eventsubTeardownPending: false,
            eventsubTeardownReconciledAt: FieldValue.serverTimestamp(),
        });
    }

    logger.info("EventSub Reconciliation Sweep Complete!");
    logger.info(`Summary:`);
    logger.info(`  - Active subscriptions kept: ${keepCount}`);
    logger.info(`  - Orphaned subscriptions deleted: ${deletedCount}`);
    logger.info(`  - Deletion failures: ${failedCount}`);
    logger.info(`  - Pending teardown flags cleared: ${pendingTeardownDocs.length}`);

  } catch (error: any) {
    logger.error(`Fatal error during reconciliation: ${error.message}`);
    process.exit(1);
  }
}

runReconciliation();
