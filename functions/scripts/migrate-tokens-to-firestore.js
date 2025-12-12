#!/usr/bin/env node
/**
 * Migrate per-user Twitch OAuth tokens from Secret Manager to Firestore.
 *
 * This knowledge-bot web UI historically stored per-user refresh tokens in Secret Manager:
 *   twitch-refresh-token-{twitchUserId}
 *
 * After the migration, tokens live in Firestore:
 *   users/{twitchUserId}/private/oauth
 *
 * Run:
 *   node scripts/migrate-tokens-to-firestore.js            # dry run
 *   node scripts/migrate-tokens-to-firestore.js --execute  # write to Firestore
 *   node scripts/migrate-tokens-to-firestore.js --execute --cleanup  # also delete secrets
 */

/* eslint-disable @typescript-eslint/no-var-requires */
const { SecretManagerServiceClient } = require("@google-cloud/secret-manager");
const admin = require("firebase-admin");

function getArgValue(flag) {
  const idx = process.argv.indexOf(flag);
  if (idx !== -1 && process.argv[idx + 1] && !process.argv[idx + 1].startsWith("--")) {
    return process.argv[idx + 1];
  }
  const withEquals = process.argv.find((a) => a.startsWith(`${flag}=`));
  if (withEquals) return withEquals.split("=").slice(1).join("=");
  return null;
}

const PROJECT_ID =
  getArgValue("--project") ||
  process.env.GOOGLE_CLOUD_PROJECT ||
  process.env.GCLOUD_PROJECT ||
  process.env.GCP_PROJECT ||
  process.env.FIREBASE_PROJECT_ID ||
  "streamsage-bot";

const EXECUTE = process.argv.includes("--execute");
const CLEANUP = process.argv.includes("--cleanup");

// NOTE: Defaults to "streamsage-bot"; pass --project to override.

if (!admin.apps.length) {
  admin.initializeApp({ projectId: PROJECT_ID });
}

const db = admin.firestore();
const secretClient = new SecretManagerServiceClient();

function extractUserId(secretName) {
  const match = secretName.match(/twitch-(access|refresh)-token-(\d+)$/);
  return match ? match[2] : null;
}

function getTokenType(secretName) {
  if (secretName.includes("access-token")) return "access";
  if (secretName.includes("refresh-token")) return "refresh";
  return null;
}

async function migrateUserTokens(userId, tokens) {
  const privateRef = db.collection("users").doc(userId).collection("private").doc("oauth");

  // eslint-disable-next-line no-console
  console.log(`\n👤 User ${userId}:`);
  // eslint-disable-next-line no-console
  console.log(`   Access token: ${tokens.access ? "✓" : "✗"}`);
  // eslint-disable-next-line no-console
  console.log(`   Refresh token: ${tokens.refresh ? "✓" : "✗"}`);

  if (!EXECUTE) {
    // eslint-disable-next-line no-console
    console.log(`   [DRY RUN] Would store in Firestore: users/${userId}/private/oauth`);
    return;
  }

  await privateRef.set(
    {
      ...(tokens.access ? { twitchAccessToken: tokens.access } : {}),
      ...(tokens.refresh ? { twitchRefreshToken: tokens.refresh } : {}),
      migratedAt: admin.firestore.FieldValue.serverTimestamp(),
      migratedFrom: "secret-manager",
    },
    { merge: true },
  );

  // eslint-disable-next-line no-console
  console.log("   ✅ Migrated to Firestore");
}

async function deleteSecret(secretName) {
  if (!EXECUTE || !CLEANUP) {
    // eslint-disable-next-line no-console
    console.log(`   [DRY RUN] Would delete secret: ${secretName}`);
    return;
  }

  try {
    await secretClient.deleteSecret({
      name: `projects/${PROJECT_ID}/secrets/${secretName}`,
    });
    // eslint-disable-next-line no-console
    console.log(`   🗑️  Deleted secret: ${secretName}`);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(`   ❌ Failed to delete ${secretName}:`, error?.message || String(error));
  }
}

async function migrateTokens() {
  // eslint-disable-next-line no-console
  console.log("🔄 User OAuth Token Migration: Secret Manager → Firestore");
  // eslint-disable-next-line no-console
  console.log("========================================================");
  // eslint-disable-next-line no-console
  console.log(`Project: ${PROJECT_ID}`);
  // eslint-disable-next-line no-console
  console.log(`Mode: ${EXECUTE ? "🔴 EXECUTE" : "🟡 DRY RUN (use --execute to run)"}`);
  // eslint-disable-next-line no-console
  console.log(`Cleanup: ${CLEANUP ? "🔴 ENABLED (will delete secrets)" : "🟢 DISABLED"}`);
  // eslint-disable-next-line no-console
  console.log("");

  const [secrets] = await secretClient.listSecrets({
    parent: `projects/${PROJECT_ID}`,
  });

  const userTokens = new Map();
  const secretsToDelete = [];

  for (const secret of secrets) {
    const secretName = secret.name.split("/").pop();
    const userId = extractUserId(secretName);
    const tokenType = getTokenType(secretName);

    if (!userId || !tokenType) continue;

    try {
      const [version] = await secretClient.accessSecretVersion({
        name: `${secret.name}/versions/latest`,
      });

      const tokenValue = version.payload?.data?.toString()?.trim();
      if (!tokenValue) continue;

      if (!userTokens.has(userId)) {
        userTokens.set(userId, {});
      }

      userTokens.get(userId)[tokenType] = tokenValue;
      secretsToDelete.push(secretName);
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error(`Failed to read ${secretName}:`, error?.message || String(error));
    }
  }

  // eslint-disable-next-line no-console
  console.log(`Found ${userTokens.size} users with OAuth tokens in Secret Manager\n`);

  for (const [userId, tokens] of userTokens) {
    await migrateUserTokens(userId, tokens);
  }

  if (CLEANUP && secretsToDelete.length > 0) {
    // eslint-disable-next-line no-console
    console.log(`\n🗑️  Cleaning up ${secretsToDelete.length} secrets from Secret Manager...`);
    for (const secretName of secretsToDelete) {
      await deleteSecret(secretName);
    }
  }

  // eslint-disable-next-line no-console
  console.log("\n📊 Migration Summary");
  // eslint-disable-next-line no-console
  console.log("===================");
  // eslint-disable-next-line no-console
  console.log(`Users migrated: ${userTokens.size}`);
  // eslint-disable-next-line no-console
  console.log(`Secrets ${CLEANUP && EXECUTE ? "deleted" : "to delete"}: ${secretsToDelete.length}`);

  if (!EXECUTE) {
    // eslint-disable-next-line no-console
    console.log("\n⚠️  This was a dry run. Run with --execute to perform the migration.");
  } else {
    // eslint-disable-next-line no-console
    console.log("\n✅ Migration complete!");
    if (!CLEANUP) {
      // eslint-disable-next-line no-console
      console.log("💡 Run with --cleanup flag to also delete secrets from Secret Manager");
    }
  }
}

migrateTokens().catch((error) => {
  // eslint-disable-next-line no-console
  console.error("Migration failed:", error);
  process.exit(1);
});


