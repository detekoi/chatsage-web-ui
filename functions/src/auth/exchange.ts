/**
 * One-time codes for handing the session token to the frontend.
 *
 * The callback used to append the seven-day session JWT to the redirect URL,
 * which put it in browser history, in the Referer of anything the landing page
 * loaded, and within reach of any analytics running on that page. It now
 * appends a single-use code with a one-minute life, and the page exchanges
 * that code for the token over POST.
 *
 * Only the SHA-256 of the code is stored, so the raw code never sits in the
 * database and a leaked row cannot be replayed against the exchange endpoint.
 * Redemption reads and deletes inside a transaction, so two racing requests
 * cannot both win.
 *
 * Expiry is enforced here on read. A Firestore TTL policy on `expiresAt` only
 * collects abandoned rows, and its deletions are best-effort within 24 hours —
 * far too loose to be the control.
 */

import { Firestore, FieldValue } from "@google-cloud/firestore";
import { randomBytes, createHash } from "crypto";
import { EXCHANGE_CODES_COLLECTION, EXCHANGE_CODE_TTL_MS } from "@/config/constants";

/**
 * Hashes a code into its document id, so the raw code is never stored.
 * @param code - The raw exchange code
 * @return Hex-encoded SHA-256 of the code
 */
function codeToDocId(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

/**
 * Mints a single-use code that stands in for the session token.
 * @param db - Firestore instance
 * @param sessionToken - The JWT the code will be exchanged for
 * @return The raw code, to be sent to the frontend
 */
export async function createExchangeCode(db: Firestore, sessionToken: string): Promise<string> {
  const code = randomBytes(32).toString("hex");

  await db.collection(EXCHANGE_CODES_COLLECTION).doc(codeToDocId(code)).set({
    sessionToken,
    createdAt: FieldValue.serverTimestamp(),
    expiresAt: new Date(Date.now() + EXCHANGE_CODE_TTL_MS),
  });

  return code;
}

export type RedeemFailureReason = "unknown_code" | "expired";

/**
 * A flat result rather than a discriminated union: this package compiles with
 * `strict: false`, under which TypeScript will not narrow a union by a boolean
 * literal discriminant. Mirrors StateResult in ./state.
 */
export interface RedeemResult {
  /** True when the code was valid and unspent. */
  ok: boolean;
  /** Set when `ok` is true. */
  sessionToken?: string;
  /** Set when `ok` is false. */
  reason?: RedeemFailureReason;
}

/**
 * Redeems a code for its session token and destroys it.
 * @param db - Firestore instance
 * @param code - The raw code supplied by the frontend
 * @return The session token, or why the code was refused
 */
export async function redeemExchangeCode(db: Firestore, code: string): Promise<RedeemResult> {
  const ref = db.collection(EXCHANGE_CODES_COLLECTION).doc(codeToDocId(code));

  return db.runTransaction(async (tx): Promise<RedeemResult> => {
    const snap = await tx.get(ref);
    if (!snap.exists) return { ok: false, reason: "unknown_code" };

    // Read before deleting, so the outcome never depends on whether writes are
    // buffered until commit.
    const data = (snap.data() ?? {}) as {
      sessionToken?: string;
      expiresAt?: Date | { toDate?: () => Date };
    };

    // Delete on every path that found a row: an expired code is spent too, so
    // it cannot be retried while the TTL sweep catches up.
    tx.delete(ref);

    // Firestore hands back a Timestamp; the emulator and tests may hand back a
    // plain Date.
    const raw = data.expiresAt;
    const expiresAt = raw instanceof Date ? raw : raw?.toDate?.();

    if (!expiresAt || expiresAt.getTime() <= Date.now()) {
      return { ok: false, reason: "expired" };
    }
    if (!data.sessionToken) return { ok: false, reason: "unknown_code" };

    return { ok: true, sessionToken: data.sessionToken };
  });
}
