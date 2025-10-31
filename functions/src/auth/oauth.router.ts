/**
 * OAuth router
 * Handles Twitch OAuth authentication flow
 */

import { Router, Request, Response } from "express";
import axios from "axios";
import crypto from "crypto";
import { getDb, FieldValue } from "@/config/database";
import {
  TWITCH_CLIENT_ID,
  TWITCH_CLIENT_SECRET,
  CALLBACK_REDIRECT_URI_CONFIG,
  FRONTEND_URL_CONFIG,
  TWITCH_TOKEN_URL,
  TWITCH_VALIDATE_URL,
  CHANNELS_COLLECTION,
} from "@/config/constants";
import { logger } from "@/config/logger";
import { redirectToFrontendWithError } from "@/utils/errors";
import { createSessionToken } from "./jwt.middleware";
import { storeRefreshToken } from "@/tokens/secretManager.service";

const router = Router();

/**
 * Builds the Twitch OAuth authorization URL
 */
function buildTwitchAuthUrl(clientId: string, redirectUri: string, state: string): URL {
  const authUrl = new URL("https://id.twitch.tv/oauth2/authorize");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "user:read:email channel:read:ads channel:manage:moderators");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("force_verify", "true");
  return authUrl;
}

/**
 * GET /auth/twitch
 * Initiates the Twitch OAuth flow
 */
router.get("/twitch", (req: Request, res: Response) => {
  logger.info("Initiating Twitch OAuth flow");

  const frontendRedirect = (req.query.redirect as string) || "/";
  const state = JSON.stringify({
    frontendRedirect,
    nonce: crypto.randomBytes(16).toString("hex"),
  });

  logger.debug("Generated OAuth state", {
    frontendRedirect,
    callbackUri: CALLBACK_REDIRECT_URI_CONFIG,
  });

  const authUrl = buildTwitchAuthUrl(
    TWITCH_CLIENT_ID,
    CALLBACK_REDIRECT_URI_CONFIG,
    state,
  );

  logger.info("Redirecting to Twitch authorization", {
    authUrl: authUrl.toString(),
  });

  res.redirect(authUrl.toString());
});

/**
 * GET /auth/twitch/callback
 * Handles the OAuth callback from Twitch
 */
router.get("/twitch/callback", async (req: Request, res: Response) => {
  logger.info("OAuth callback received");

  const {
    code,
    state: twitchQueryState,
    error: twitchError,
    error_description: twitchErrorDescription,
  } = req.query;

  // Handle explicit Twitch errors
  if (twitchError) {
    logger.error("Twitch OAuth error", {
      error: twitchError,
      description: twitchErrorDescription,
    });
    return redirectToFrontendWithError(
      res,
      twitchError as string,
      twitchErrorDescription as string,
      twitchQueryState as string,
    );
  }

  // Validate state parameter (CSRF protection)
  if (!twitchQueryState) {
    logger.error("Missing state parameter in callback");
    return redirectToFrontendWithError(
      res,
      "invalid_request",
      "Missing state parameter",
      null,
    );
  }

  let parsedState: { nonce?: string; frontendRedirect?: string };
  try {
    parsedState = JSON.parse(twitchQueryState as string);
    if (!parsedState.nonce || !parsedState.frontendRedirect) {
      throw new Error("Invalid state structure");
    }
    logger.debug("State validated successfully");
  } catch (stateError) {
    logger.error("State validation failed", {
      error: (stateError as Error).message,
    });
    return redirectToFrontendWithError(
      res,
      "invalid_state",
      "State validation failed - possible CSRF attack",
      twitchQueryState as string,
    );
  }

  try {
    const db = getDb();

    // Exchange authorization code for tokens
    logger.info("Exchanging authorization code for tokens");

    const tokenResponse = await axios.post(TWITCH_TOKEN_URL, null, {
      params: {
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        code: code as string,
        grant_type: "authorization_code",
        redirect_uri: CALLBACK_REDIRECT_URI_CONFIG,
      },
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000,
    });

    logger.info("Token exchange successful");

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;

    if (!accessToken || !refreshToken) {
      throw new Error("Missing access or refresh token from Twitch");
    }

    // Validate the access token
    await axios.get(TWITCH_VALIDATE_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 15000,
    });

    logger.info("Token validated successfully");

    // Fetch user information
    const userResponse = await axios.get("https://api.twitch.tv/helix/users", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Client-ID": TWITCH_CLIENT_ID,
      },
      timeout: 15000,
    });

    const twitchUserData = userResponse.data?.data?.[0];

    if (!twitchUserData) {
      throw new Error("Failed to get user info from Twitch");
    }

    const twitchUser = {
      id: twitchUserData.id,
      login: twitchUserData.login,
      displayName: twitchUserData.display_name,
      email: twitchUserData.email,
    };

    logger.info("Twitch user fetched successfully", {
      login: twitchUser.login,
      userId: twitchUser.id,
    });

    // Store refresh token in Secret Manager
    logger.info("Storing refresh token in Secret Manager", {
      userId: twitchUser.id,
    });

    const secretPath = await storeRefreshToken(twitchUser.id, refreshToken);

    // Store user data in Firestore
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(twitchUser.login);
    await userDocRef.set(
      {
        refreshTokenSecretPath: secretPath,
        twitchUserId: twitchUser.id,
        displayName: twitchUser.displayName,
        email: twitchUser.email || null,
        lastLoginAt: FieldValue.serverTimestamp(),
        needsTwitchReAuth: false,
        lastTokenError: null,
        lastTokenErrorAt: null,
      },
      { merge: true },
    );

    logger.info("User data stored in Firestore", {
      login: twitchUser.login,
    });

    // Create JWT session token
    const sessionToken = createSessionToken({
      login: twitchUser.login,
      userId: twitchUser.id,
      displayName: twitchUser.displayName,
      email: twitchUser.email,
    });

    logger.info("JWT session token created", { login: twitchUser.login });

    // Redirect to frontend auth-complete page
    // NOTE: Session token in URL is a known limitation due to cross-origin setup
    // For same-domain setup, use HTTP-only cookies instead
    const frontendAuthCompleteUrl = new URL(FRONTEND_URL_CONFIG);
    frontendAuthCompleteUrl.pathname = "/auth-complete.html";
    frontendAuthCompleteUrl.searchParams.append("user_login", twitchUser.login);
    frontendAuthCompleteUrl.searchParams.append("user_id", twitchUser.id);
    frontendAuthCompleteUrl.searchParams.append("state", twitchQueryState as string);
    frontendAuthCompleteUrl.searchParams.append("session_token", sessionToken);

    logger.info("Redirecting to frontend auth-complete", {
      login: twitchUser.login,
      redirectUrl: frontendAuthCompleteUrl.pathname,
    });

    return res.redirect(frontendAuthCompleteUrl.toString());
  } catch (error: unknown) {
    const err = error as { response?: { data?: unknown }; message: string; stack?: string };
    logger.error("OAuth callback error", {
      error: err.response ? JSON.stringify(err.response.data) : err.message,
      stack: err.stack,
    });

    return redirectToFrontendWithError(
      res,
      "auth_failed",
      "Authentication failed with Twitch due to an internal server error",
      twitchQueryState as string,
    );
  }
});

export default router;
