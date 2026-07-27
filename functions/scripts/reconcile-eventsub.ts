/**
 * One-shot EventSub reconciliation sweep.
 *
 * Deletes "phantom" subscriptions: subscriptions Twitch still holds for channels
 * that are no longer active in managedChannels. These accumulate from removals
 * that happened before /api/bot/remove tore subscriptions down itself.
 *
 * Runs in DRY-RUN by default and only deletes when passed --apply.
 *
 * Prerequisites (this script imports compiled output via the "@" alias):
 *   npm run build
 *
 * Required environment:
 *   GOOGLE_APPLICATION_CREDENTIALS (or ambient ADC) pointing at the right project
 *   TWITCH_CLIENT_ID
 *   TWITCH_CLIENT_SECRET
 *
 * Usage:
 *   npx ts-node scripts/reconcile-eventsub.ts            # report only
 *   npx ts-node scripts/reconcile-eventsub.ts --apply    # actually delete
 */

import { initializeApp } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
// Register module alias before the "@"-prefixed imports below are required.
// TypeScript resolves "@/*" to src/*.ts for type-checking; at runtime it has to
// resolve to the compiled output instead. Anchor on the functions root so the
// alias is correct both under ts-node (scripts/) and when the compiled copy in
// lib/scripts/ is executed — resolving relative to __dirname alone gives
// lib/lib/src for the latter, which does not exist.
import moduleAlias from "module-alias";
import * as path from "path";

const functionsRoot = __filename.endsWith(".ts")
  ? path.join(__dirname, "..") // scripts/ -> functions/
  : path.join(__dirname, "..", ".."); // lib/scripts/ -> functions/
moduleAlias.addAlias("@", path.join(functionsRoot, "lib", "src"));

import { getAppAccessToken } from "@/twitch/appToken.service";
import { getTwitchSubscriptionsPaginated, deleteTwitchSubscription } from "@/twitch/eventsub.service";
import { CHANNELS_COLLECTION } from "@/config/constants";
import { logger } from "@/config/logger";

const APPLY = process.argv.includes("--apply");

interface Subscription {
  id: string;
  type: string;
  condition?: Record<string, string | undefined>;
}

/**
 * The broadcaster a subscription belongs to.
 *
 * Not every type keys on broadcaster_user_id — channel.raid uses
 * to_broadcaster_user_id. Returns null when no channel-identifying field is
 * present, so the caller can skip rather than delete. Deliberately does NOT
 * String()-coerce: String(undefined) is "undefined", a truthy value that would
 * match no active channel and get the subscription deleted.
 */
function getSubscriptionBroadcasterId(sub: Subscription): string | null {
  const condition = sub.condition || {};
  const id = condition.broadcaster_user_id ?? condition.to_broadcaster_user_id;
  return id ? String(id) : null;
}

async function runReconciliation() {
  logger.info(
    APPLY
      ? "Starting EventSub reconciliation sweep (APPLY — will delete)"
      : "Starting EventSub reconciliation sweep (DRY RUN — pass --apply to delete)",
  );

  try {
    for (const varName of ["TWITCH_CLIENT_ID", "TWITCH_CLIENT_SECRET"]) {
      if (!process.env[varName]) {
        logger.error(`${varName} is not set. Aborting.`);
        process.exit(1);
      }
    }

    initializeApp();
    const db = getFirestore();

    // 1. Active channels from Firestore
    logger.info(`Fetching channels from ${CHANNELS_COLLECTION}...`);
    const channelsSnapshot = await db.collection(CHANNELS_COLLECTION).get();

    const activeBroadcasterIds = new Set<string>();
    const pendingTeardownByBroadcaster = new Map<
      string,
      FirebaseFirestore.QueryDocumentSnapshot
    >();

    channelsSnapshot.forEach((doc) => {
      const data = doc.data();
      const broadcasterId = String(data.twitchUserId || doc.id);

      if (data.isActive) {
        activeBroadcasterIds.add(broadcasterId);
      }
      if (data.eventsubTeardownPending === true) {
        pendingTeardownByBroadcaster.set(broadcasterId, doc);
      }
    });

    logger.info(`Found ${activeBroadcasterIds.size} active channels.`);
    logger.info(`Found ${pendingTeardownByBroadcaster.size} channels flagged teardown-pending.`);

    // Safety valve: an empty active set almost certainly means wrong project,
    // wrong credentials, or a failed read — not "delete every subscription".
    if (activeBroadcasterIds.size === 0) {
      logger.error(
        `${CHANNELS_COLLECTION} returned no active channels. Refusing to treat ` +
          "every subscription as orphaned — check credentials and project. Aborting.",
      );
      process.exit(1);
    }

    // 2. All subscriptions from Twitch (paginated)
    logger.info("Fetching all EventSub subscriptions from Twitch...");
    const appAccessToken = await getAppAccessToken();
    const subscriptions = (await getTwitchSubscriptionsPaginated(appAccessToken)) as Subscription[];

    logger.info(`Total EventSub subscriptions on Twitch: ${subscriptions.length}`);

    // 3. Reconcile
    let deleted = 0;
    let failed = 0;
    let kept = 0;
    let skipped = 0;
    const failedBroadcasterIds = new Set<string>();

    for (const sub of subscriptions) {
      const broadcasterId = getSubscriptionBroadcasterId(sub);

      if (!broadcasterId) {
        skipped++;
        logger.warn(
          `Subscription ${sub.id} (${sub.type}) has no broadcaster id in its ` +
            "condition. Skipping — not treating it as orphaned.",
        );
        continue;
      }

      if (activeBroadcasterIds.has(broadcasterId)) {
        kept++;
        continue;
      }

      if (!APPLY) {
        deleted++;
        logger.info(`[DRY RUN] Would delete ${sub.type} for broadcaster ${broadcasterId} (${sub.id})`);
        continue;
      }

      try {
        await deleteTwitchSubscription(appAccessToken, sub.id);
        deleted++;
        logger.info(`Deleted ${sub.type} for broadcaster ${broadcasterId} (${sub.id})`);
      } catch (err: unknown) {
        failed++;
        failedBroadcasterIds.add(broadcasterId);
        const message = err instanceof Error ? err.message : String(err);
        logger.error(`Failed to delete subscription ${sub.id}: ${message}`);

        // Back off on rate limiting. deleteTwitchSubscription only suppresses
        // 404s, so a 429 lands here — without this the loop would retry the
        // next subscription immediately, hammering hardest exactly when Twitch
        // has asked us to slow down.
        const response = (err as {
          response?: { status?: number; headers?: Record<string, string> };
        })?.response;

        if (response?.status === 429) {
          // Twitch's Helix API signals rate limits via Ratelimit-Reset (a Unix
          // timestamp, in seconds) rather than the standard Retry-After header.
          const resetAt = Number(response.headers?.["ratelimit-reset"]);
          const waitMs = Number.isFinite(resetAt) && resetAt > 0
            ? Math.max(resetAt * 1000 - Date.now(), 0)
            : 5000;
          logger.warn(`Rate limited by Twitch. Backing off ${waitMs}ms.`);
          await new Promise((resolve) => setTimeout(resolve, waitMs));
        }
      } finally {
        // Throttle every request, not only the successful ones (~10/s, well
        // under Twitch's 800/min).
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }

    // 4. Clear teardown flags — only for channels that fully reconciled, so a
    //    channel with a failed deletion stays flagged for the next sweep.
    let flagsCleared = 0;

    if (APPLY) {
      for (const [broadcasterId, doc] of pendingTeardownByBroadcaster) {
        if (failedBroadcasterIds.has(broadcasterId)) {
          logger.warn(`Keeping teardown-pending flag for ${broadcasterId} — deletions failed.`);
          continue;
        }

        // Use a precondition with updateTime to prevent a race condition where
        // a concurrent removal re-sets eventsubTeardownPending during the sweep.
        try {
          await doc.ref.update({
            eventsubTeardownPending: false,
            eventsubTeardownReconciledAt: FieldValue.serverTimestamp(),
          }, { lastUpdateTime: doc.updateTime });
          flagsCleared++;
        } catch (updateErr: unknown) {
          const err = updateErr as { code?: number };
          if (err.code === 9) { // FAILED_PRECONDITION
            logger.warn(`Teardown flag for ${broadcasterId} was modified concurrently. Skipping clear.`);
          } else {
            throw updateErr;
          }
        }
      }
    }

    logger.info("EventSub reconciliation sweep complete.");
    logger.info("Summary:");
    logger.info(`  - Subscriptions kept (active channels): ${kept}`);
    logger.info(`  - Skipped (no broadcaster id in condition): ${skipped}`);
    logger.info(`  - Orphaned ${APPLY ? "deleted" : "that would be deleted"}: ${deleted}`);
    logger.info(`  - Deletion failures: ${failed}`);
    logger.info(`  - Teardown flags cleared: ${flagsCleared}`);

    if (!APPLY && deleted > 0) {
      logger.info("Dry run only. Re-run with --apply to perform these deletions.");
    }

    process.exit(failed > 0 ? 1 : 0);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`Fatal error during reconciliation: ${message}`);
    process.exit(1);
  }
}

runReconciliation().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  logger.error(`Unhandled error during reconciliation: ${message}`);
  process.exit(1);
});
