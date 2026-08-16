/**
 * Tests for auth/exchange.ts and POST /auth/exchange
 *
 * The property that matters: a code stands in for the session token exactly
 * once, briefly, and the raw code is never what gets stored.
 */

import express from "express";
import request from "supertest";
import { createHash } from "crypto";
import { createExchangeCode, redeemExchangeCode } from "@/auth/exchange";
import { EXCHANGE_CODES_COLLECTION } from "@/config/constants";

jest.mock("@/config/logger", () => ({
  logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn() },
}));

/**
 * A Firestore stand-in with just enough behaviour for the exchange: document
 * storage keyed by id, and a transaction whose reads and deletes apply
 * immediately, which is all these tests observe.
 */
function createFakeDb() {
  const docs = new Map<string, Record<string, unknown>>();

  const docRef = (id: string) => ({
    id,
    set: async (data: Record<string, unknown>) => {
      docs.set(id, data);
    },
    get: async () => {
      // Snapshot eagerly, as Firestore does: a snapshot is a point-in-time
      // read and must not follow later deletes.
      const snapshot = docs.get(id);
      return { exists: snapshot !== undefined, data: () => snapshot };
    },
  });

  return {
    docs,
    collection: (name: string) => {
      if (name !== EXCHANGE_CODES_COLLECTION) throw new Error(`unexpected collection ${name}`);
      return { doc: docRef };
    },
    runTransaction: async <T>(fn: (tx: {
      get: (ref: { get: () => Promise<unknown> }) => Promise<unknown>;
      delete: (ref: { id: string }) => void;
    }) => Promise<T>): Promise<T> => fn({
      get: (ref) => ref.get(),
      delete: (ref) => {
        docs.delete(ref.id);
      },
    }),
  };
}

/* eslint-disable @typescript-eslint/no-explicit-any */

describe("exchange codes", () => {
  it("returns a high-entropy code", async () => {
    const db = createFakeDb();
    const code = await createExchangeCode(db as any, "the.session.jwt");

    expect(code).toMatch(/^[0-9a-f]{64}$/);
  });

  it("stores only the hash of the code, never the code itself", async () => {
    const db = createFakeDb();
    const code = await createExchangeCode(db as any, "the.session.jwt");

    const expectedId = createHash("sha256").update(code).digest("hex");
    expect([...db.docs.keys()]).toEqual([expectedId]);
    expect(JSON.stringify([...db.docs.values()])).not.toContain(code);
  });

  it("redeems a fresh code for its session token", async () => {
    const db = createFakeDb();
    const code = await createExchangeCode(db as any, "the.session.jwt");

    const result = await redeemExchangeCode(db as any, code);

    expect(result.ok).toBe(true);
    expect(result.sessionToken).toBe("the.session.jwt");
  });

  it("refuses a code the second time, so it cannot be replayed", async () => {
    const db = createFakeDb();
    const code = await createExchangeCode(db as any, "the.session.jwt");

    await redeemExchangeCode(db as any, code);
    const second = await redeemExchangeCode(db as any, code);

    expect(second.ok).toBe(false);
    expect(second.reason).toBe("unknown_code");
    expect(second.sessionToken).toBeUndefined();
  });

  it("refuses an unknown code", async () => {
    const db = createFakeDb();

    const result = await redeemExchangeCode(db as any, "f".repeat(64));

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("unknown_code");
  });

  it("refuses an expired code and spends it anyway", async () => {
    const db = createFakeDb();
    const code = await createExchangeCode(db as any, "the.session.jwt");

    // Rewind the stored expiry rather than waiting out the real TTL.
    const id = createHash("sha256").update(code).digest("hex");
    const stored = db.docs.get(id) as { expiresAt: Date };
    stored.expiresAt = new Date(Date.now() - 1000);

    const result = await redeemExchangeCode(db as any, code);

    expect(result.ok).toBe(false);
    expect(result.reason).toBe("expired");
    expect(db.docs.has(id)).toBe(false);
  });

  it("enforces expiry itself rather than trusting the Firestore TTL sweep", async () => {
    const db = createFakeDb();
    const code = await createExchangeCode(db as any, "the.session.jwt");

    const id = createHash("sha256").update(code).digest("hex");
    const stored = db.docs.get(id) as { expiresAt: Date };

    // A TTL policy deletes within ~24h of expiry, so a row can outlive its
    // expiresAt by a long way and must still be refused.
    stored.expiresAt = new Date(Date.now() - 23 * 60 * 60 * 1000);

    expect((await redeemExchangeCode(db as any, code)).ok).toBe(false);
  });
});

describe("POST /auth/exchange", () => {
  const fakeDb = createFakeDb();

  /**
   * Mounts the oauth router over the fake Firestore.
   * @return Express app under test
   */
  function createApp() {
    jest.resetModules();
    jest.doMock("@/config/database", () => ({
      getDb: () => fakeDb,
      FieldValue: { serverTimestamp: () => new Date() },
    }));

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const router = require("@/auth/oauth.router").default;

    const app = express();
    app.use(express.json());
    app.use("/auth", router);
    return app;
  }

  it("rejects a request with no code", async () => {
    const res = await request(createApp()).post("/auth/exchange").send({});

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  it("rejects an unknown code without leaking why", async () => {
    const res = await request(createApp())
      .post("/auth/exchange")
      .send({ code: "f".repeat(64) });

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.session_token).toBeUndefined();
  });

  it("returns the session token for a valid code, once", async () => {
    const app = createApp();
    const code = await createExchangeCode(fakeDb as any, "the.session.jwt");

    const first = await request(app).post("/auth/exchange").send({ code });
    expect(first.status).toBe(200);
    expect(first.body.session_token).toBe("the.session.jwt");

    const second = await request(app).post("/auth/exchange").send({ code });
    expect(second.status).toBe(400);
    expect(second.body.session_token).toBeUndefined();
  });
});
