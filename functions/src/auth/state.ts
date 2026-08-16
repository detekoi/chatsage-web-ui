/**
 * OAuth state binding.
 *
 * The `state` parameter that round-trips through Twitch carries nothing but an
 * opaque nonce. Everything the callback needs to recover — currently just
 * `frontendRedirect` — travels in a server-set HttpOnly cookie instead, so it
 * cannot be edited by whoever hits the callback.
 *
 * The cookie is deliberately not signed. A signature would only prove that we
 * minted the value, and an attacker can mint one by running the flow himself,
 * so it blocks nothing here. What defends this cookie is the nonce entropy,
 * HttpOnly + Secure + SameSite=Lax, host-only scope, the ten-minute lifetime,
 * single use, and the timing-safe comparison below.
 *
 * The cookie name is forced on us: `api.wildcat.chat` and `app.wildcat.chat`
 * are Firebase Hosting sites that rewrite to this Function, and Hosting strips
 * every cookie except `__session` before forwarding. That rules out the
 * `__Host-` prefix, so a sibling subdomain planting a cookie (cookie tossing)
 * is not structurally blocked.
 */

import { Request, Response } from "express";
import { randomBytes, timingSafeEqual } from "crypto";
import { IS_TEST } from "@/config/constants";

/** Forced by Firebase Hosting — see the module comment. */
export const STATE_COOKIE_NAME = "__session";

/** Long enough to finish a Twitch login, short enough to limit replay. */
const STATE_TTL_MS = 10 * 60 * 1000;

/** Local emulator runs over plain HTTP, where a Secure cookie is dropped. */
const IS_EMULATOR = process.env.FUNCTIONS_EMULATOR === "true";

/**
 * What the callback needs to know, carried in the cookie rather than in
 * `state` so that it is server-set and cannot be steered by the caller.
 */
export interface OAuthStatePayload {
  /** Where the frontend asked to land after login. */
  r: string;
}

interface StoredState {
  n: string;
  p: OAuthStatePayload;
}

export type StateFailureReason =
  | "missing_cookie"
  | "missing_state"
  | "malformed_cookie"
  | "mismatch";

/**
 * A flat result rather than a discriminated union: this package compiles with
 * `strict: false`, under which TypeScript will not narrow a union by a boolean
 * literal discriminant.
 */
export interface StateResult {
  /** True when the callback's `state` matched the cookie. */
  ok: boolean;
  /** Set when `ok` is true. */
  payload?: OAuthStatePayload;
  /** Set when `ok` is false. */
  reason?: StateFailureReason;
}

/**
 * Cookie attributes. No `domain`, so the cookie is host-only. `lax` rather
 * than `strict` because the Twitch → callback hop is a cross-site top-level
 * GET navigation; a `strict` cookie would not be sent and the flow would break.
 */
function cookieOptions() {
  return {
    httpOnly: true,
    secure: !IS_TEST && !IS_EMULATOR,
    sameSite: "lax" as const,
    path: "/",
  };
}

/**
 * Mints a nonce, stores it with the routing payload in the state cookie, and
 * returns the nonce to send to Twitch as `state`.
 * @param res - Express response object, for the Set-Cookie header
 * @param payload - Routing context to recover on the callback
 * @return The opaque nonce to use as the OAuth `state` parameter
 */
export function issueState(res: Response, payload: OAuthStatePayload): string {
  const nonce = randomBytes(32).toString("hex");
  const stored: StoredState = { n: nonce, p: payload };

  res.cookie(STATE_COOKIE_NAME, JSON.stringify(stored), {
    ...cookieOptions(),
    maxAge: STATE_TTL_MS,
  });

  return nonce;
}

/**
 * Reads and clears the state cookie, then checks it against `req.query.state`.
 * The cookie is cleared on every path, valid or not, so a state is single-use.
 * @param req - Express request object, read for the cookie and `state`
 * @param res - Express response object, for the clearing Set-Cookie header
 * @return The stored payload on a match, or the reason it failed
 */
export function consumeState(req: Request, res: Response): StateResult {
  const raw = readCookie(req, STATE_COOKIE_NAME);
  res.clearCookie(STATE_COOKIE_NAME, cookieOptions());

  if (!raw) return { ok: false, reason: "missing_cookie" };

  const queryState = req.query.state;
  if (typeof queryState !== "string" || !queryState) {
    return { ok: false, reason: "missing_state" };
  }

  let stored: StoredState;
  try {
    stored = JSON.parse(raw) as StoredState;
  } catch {
    return { ok: false, reason: "malformed_cookie" };
  }

  if (!stored || typeof stored.n !== "string" || !stored.p || typeof stored.p.r !== "string") {
    return { ok: false, reason: "malformed_cookie" };
  }

  if (!nonceMatches(stored.n, queryState)) {
    return { ok: false, reason: "mismatch" };
  }

  return { ok: true, payload: stored.p };
}

/**
 * Constant-time string comparison. `timingSafeEqual` throws on unequal
 * lengths, so the length is checked first and short-circuits.
 * @param a - Expected value
 * @param b - Supplied value
 * @return True if the two are identical
 */
function nonceMatches(a: string, b: string): boolean {
  const expected = Buffer.from(a, "utf8");
  const supplied = Buffer.from(b, "utf8");
  if (expected.length !== supplied.length) return false;
  return timingSafeEqual(expected, supplied);
}

/**
 * Reads a cookie straight off the request header rather than through
 * `cookie-parser`, so that state binding does not depend on middleware order.
 * @param req - Express request object
 * @param name - Cookie name to look for
 * @return The decoded cookie value, or null if absent or undecodable
 */
function readCookie(req: Request, name: string): string | null {
  const header = req.headers.cookie;
  if (!header) return null;

  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      return null;
    }
  }

  return null;
}
