/**
 * Twitch OAuth 2.0 Authentication and Bot Management API
 *
 * This Firebase Cloud Function provides Twitch OAuth authentication for users
 * who want to add the StreamSage bot to their Twitch channel. It implements
 * the full OAuth flow including token refresh, validation, and management.
 *
 * Key features:
 * - Complete Twitch OAuth 2.0 authentication flow
 * - Secure token storage in Firestore
 * - Token refresh with retry logic and error handling
 * - Bot management (add/remove)
 * - User authentication state tracking
 *
 * Environment variables required:
 * - TWITCH_CLIENT_ID: Your Twitch application client ID
 * - TWITCH_CLIENT_SECRET: Your Twitch application client secret
 * - CALLBACK_URL: The OAuth callback URL (must match Twitch dev console)
 * - FRONTEND_URL: The URL of your frontend application
 * - JWT_SECRET_KEY: Secret for signing JWT tokens
 * - SESSION_COOKIE_SECRET: Secret for cookie signing
 */

const functions = require("firebase-functions"); // Still needed for exports.webUi
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const {Firestore, FieldValue} = require("@google-cloud/firestore");
let db;
try {
  db = new Firestore();
  console.log("[CloudFunctions] Firestore client initialized.");
} catch (e) {
  console.error("[CloudFunctions] Firestore client init error:", e);
}

const CHANNELS_COLLECTION = "managedChannels";

const app = express();

// --- Environment Configuration using process.env for 2nd Gen Functions ---
// These will be loaded from .env files (e.g., .env.streamsage-bot for deployed, .env for local emulator)
const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID;
// The client secret comes from environment variables and should be kept secure
const TWITCH_CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET;
const CALLBACK_REDIRECT_URI_CONFIG = process.env.CALLBACK_URL;
const FRONTEND_URL_CONFIG = process.env.FRONTEND_URL;
const JWT_SECRET = process.env.JWT_SECRET_KEY;
const JWT_EXPIRATION = "1h";
const SESSION_SECRET_FOR_COOKIE_PARSER = process.env.SESSION_COOKIE_SECRET;

if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET || !CALLBACK_REDIRECT_URI_CONFIG || !FRONTEND_URL_CONFIG || !JWT_SECRET || !SESSION_SECRET_FOR_COOKIE_PARSER) {
  console.error("CRITICAL: One or more environment variables are missing. Check .env files and deployment configuration.");

  // Log which specific variables are missing for easier debugging
  const missingVars = [];
  if (!TWITCH_CLIENT_ID) missingVars.push("TWITCH_CLIENT_ID");
  if (!TWITCH_CLIENT_SECRET) missingVars.push("TWITCH_CLIENT_SECRET");
  if (!CALLBACK_REDIRECT_URI_CONFIG) missingVars.push("CALLBACK_URL");
  if (!FRONTEND_URL_CONFIG) missingVars.push("FRONTEND_URL");
  if (!JWT_SECRET) missingVars.push("JWT_SECRET_KEY");
  if (!SESSION_SECRET_FOR_COOKIE_PARSER) missingVars.push("SESSION_COOKIE_SECRET");

  console.error(`Missing environment variables: ${missingVars.join(", ")}`);
  console.error("Functions will not work correctly without these variables. Set them in your .env file or in your deployment configuration.");

  // We don't throw an error here as it would prevent the function from initializing at all.
  // Instead, individual routes will handle missing configuration gracefully.
}

app.use(cookieParser(SESSION_SECRET_FOR_COOKIE_PARSER));

// Improved CORS Middleware
app.use((req, res, next) => {
  const allowedOrigins = [
    FRONTEND_URL_CONFIG, // This will be the live URL from .env.streamsage-bot when deployed or local from .env when emulated
    "http://127.0.0.1:5002", // Keep for local emulator access
    "http://localhost:5002", // Keep for local emulator access
  ].filter(Boolean);

  const origin = req.headers.origin;
  console.log(`CORS Check: Request Origin: ${origin}, Allowed Production Frontend URL: ${FRONTEND_URL_CONFIG}`);

  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    console.log(`CORS Check: Origin ${origin} is allowed.`);
  } else {
    if (origin) {
      console.warn(`CORS Check: Origin ${origin} is NOT in allowed list: ${allowedOrigins.join(", ")}`);
    }
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    console.log(`CORS Check: Responding to OPTIONS request for origin: ${origin}`);
    return res.sendStatus(204);
  }
  next();
});

const TWITCH_AUTH_URL = "https://id.twitch.tv/oauth2/authorize";
const TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token";
const TWITCH_VALIDATE_URL = "https://id.twitch.tv/oauth2/validate";


// Route: /auth/twitch/initiate
app.get("/auth/twitch/initiate", (req, res) => {
  console.log("--- /auth/twitch/initiate HIT ---");
  // Removed 'conf' variable as it's not used and was from functions.config()
  const currentTwitchClientId = TWITCH_CLIENT_ID;
  const currentCallbackRedirectUri = CALLBACK_REDIRECT_URI_CONFIG;

  console.log("TWITCH_CLIENT_ID from env:", currentTwitchClientId);
  console.log("CALLBACK_REDIRECT_URI_CONFIG from env:", currentCallbackRedirectUri);


  if (!currentTwitchClientId || !currentCallbackRedirectUri) {
    console.error("Config missing for /auth/twitch/initiate: TWITCH_CLIENT_ID or CALLBACK_URL not found in environment variables.");
    return res.status(500).json({success: false, error: "Server configuration error for Twitch auth."});
  }

  const state = crypto.randomBytes(16).toString("hex");

  // Try multiple cookie settings approaches to maximize compatibility
  // First one with SameSite=None for cross-site redirects
  res.cookie("twitch_oauth_state", state, {
    signed: true,
    httpOnly: true,
    secure: true,
    maxAge: 300000, // 5 minutes
    sameSite: "None",
  });

  // Backup cookie with Lax setting
  res.cookie("twitch_oauth_state_lax", state, {
    signed: true,
    httpOnly: true,
    secure: true,
    maxAge: 300000, // 5 minutes
    sameSite: "Lax",
  });

  // Also store state in session if available
  if (req.session) {
    req.session.twitch_oauth_state = state;
  }

  const params = new URLSearchParams({
    client_id: currentTwitchClientId,
    redirect_uri: currentCallbackRedirectUri, // This will be ngrok or live URL from .env
    response_type: "code",
    scope: "user:read:email",
    state: state,
    force_verify: "true", // Consider "false" for production for better UX
  });
  const twitchAuthUrl = `${TWITCH_AUTH_URL}?${params.toString()}`;

  console.log(`Generated state: ${state}`);
  console.log(`Twitch Auth URL to be sent to frontend: ${twitchAuthUrl}`);

  // Store the state in the response so the frontend can use it if cookies fail
  res.json({
    success: true,
    twitchAuthUrl: twitchAuthUrl,
    state: state,
  });
});

// Route: /auth/twitch/callback
app.get("/auth/twitch/callback", async (req, res) => {
  console.log("--- /auth/twitch/callback HIT ---");
  console.log("Callback Request Query Params:", JSON.stringify(req.query));
  const { code, state: twitchQueryState, error: twitchError, error_description: twitchErrorDescription } = req.query;

  // Clear any state-related cookies that might have been set
  res.clearCookie("twitch_oauth_state");
  res.clearCookie("twitch_oauth_state_lax");
  if (req.session) {
    delete req.session.twitch_oauth_state;
  }

  if (twitchError) {
    console.error(`Twitch OAuth explicit error: ${twitchError} - ${twitchErrorDescription}`);
    return redirectToFrontendWithError(res, twitchError, twitchErrorDescription, twitchQueryState);
  }

  // The client-side (in auth-complete.html) is now responsible for state validation
  // against sessionStorage. We will proceed with the code exchange.
  // The original server-side check is removed due to browser cross-site cookie restrictions.

  try {
    console.log("Exchanging code for token. Callback redirect_uri used for exchange:", CALLBACK_REDIRECT_URI_CONFIG);
    const tokenResponse = await axios.post(
      TWITCH_TOKEN_URL,
      new URLSearchParams({
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        code: code,
        grant_type: "authorization_code",
        redirect_uri: CALLBACK_REDIRECT_URI_CONFIG,
      }).toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      },
    );
    const { access_token: accessToken, refresh_token: refreshToken, expires_in: expiresIn } = tokenResponse.data;
    console.log("Access token and refresh token received from Twitch.");

    if (!accessToken || !refreshToken) {
      console.error("Missing access_token or refresh_token from Twitch.", tokenResponse.data);
      throw new Error("Twitch did not return the expected tokens.");
    }

    const accessTokenExpiresAt = new Date(Date.now() + expiresIn * 1000);

    const validateResponse = await axios.get(TWITCH_VALIDATE_URL, {
      headers: {Authorization: `OAuth ${accessToken}`},
    });

    if (validateResponse.data && validateResponse.data.user_id) {
      const twitchUser = {
        id: validateResponse.data.user_id,
        login: validateResponse.data.login.toLowerCase(),
        displayName: validateResponse.data.login,
      };
      console.log(`[AuthCallback] User ${twitchUser.login} authenticated and validated.`);

      if (!JWT_SECRET) { // from .env
        console.error("JWT_SECRET is not configured in environment variables.");
        return res.status(500).send("Server configuration error (JWT signing).");
      }

      const appTokenPayload = {
        userId: twitchUser.id,
        userLogin: twitchUser.login,
        displayName: twitchUser.displayName,
      };
      const appSessionToken = jwt.sign(appTokenPayload, JWT_SECRET, {expiresIn: JWT_EXPIRATION});
      console.log(`Generated app session token for ${twitchUser.login}`);

      const frontendAuthCompleteUrl = new URL(FRONTEND_URL_CONFIG); // from .env
      frontendAuthCompleteUrl.pathname = "/auth-complete.html";
      frontendAuthCompleteUrl.searchParams.append("user_login", twitchUser.login);
      frontendAuthCompleteUrl.searchParams.append("user_id", twitchUser.id);
      frontendAuthCompleteUrl.searchParams.append("state", twitchQueryState);
      frontendAuthCompleteUrl.searchParams.append("session_token", appSessionToken);

      console.log(`Redirecting to frontend auth-complete page: ${frontendAuthCompleteUrl.toString()}`);

      // Store tokens in Firestore
      if (db) {
        const userDocRef = db.collection(CHANNELS_COLLECTION).doc(twitchUser.login);
        try {
          await userDocRef.set({
            twitchAccessToken: accessToken,
            twitchRefreshToken: refreshToken, // Encrypt this in a real production system if desired
            twitchAccessTokenExpiresAt: accessTokenExpiresAt,
            twitchUserId: twitchUser.id,
            displayName: twitchUser.displayName,
            // Preserve other fields by merging, or set them if this is the first time
            lastLoginAt: FieldValue.serverTimestamp(),
            // Clear any previous error flags or re-auth requirements
            needsTwitchReAuth: false,
            lastTokenError: null,
            lastTokenErrorAt: null,
          }, {merge: true});
          console.log(`Twitch tokens stored for user ${twitchUser.login}`);

          // Now validate the tokens are working by attempting to use them
          try {
            // Use the validate endpoint to ensure the tokens work properly
            await axios.get(TWITCH_VALIDATE_URL, {
              headers: {
                Authorization: `OAuth ${accessToken}`,
              },
            });
            console.log(`Twitch tokens for ${twitchUser.login} successfully validated.`);
          } catch (validateError) {
            console.error(`Failed to validate new tokens for ${twitchUser.login}:`, validateError.message);
            // We'll continue the auth flow anyway since we already got tokens, but log the validation failure
          }
        } catch (dbError) {
          console.error(`Error storing Twitch tokens for ${twitchUser.login}:`, dbError);
          // Decide if this is a fatal error for the auth flow or just log and continue
          // For now, we'll log and continue, but you might want to send an error response.
        }
      } else {
        console.error("Firestore (db) not initialized. Cannot store Twitch tokens.");
        // This is a server configuration issue, likely fatal for storing tokens.
      }

      return res.redirect(frontendAuthCompleteUrl.toString());
    } else {
      console.error("Failed to validate token or get user info from Twitch after token exchange.");
      throw new Error("Failed to validate token or get user info from Twitch.");
    }
  } catch (error) {
    console.error("[AuthCallback] Twitch OAuth callback error:", error.response ? JSON.stringify(error.response.data, null, 2) : error.message, error.stack);
    // Try to redirect to frontend with generic error if possible
    return redirectToFrontendWithError(res, "auth_failed", "Authentication failed with Twitch due to an internal server error.", twitchQueryState);
  }
});

// JWT Authentication Middleware
const authenticateApiRequest = (req, res, next) => {
  console.log(`--- authenticateApiRequest for ${req.path} ---`);
  const authHeader = req.headers.authorization;
  console.log("Received Authorization Header:", authHeader);

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    console.warn("API Auth Middleware: Missing or malformed Authorization header.");
    return res.status(401).json({success: false, message: "Unauthorized: Missing or malformed token."});
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    console.warn("API Auth Middleware: Token not found after Bearer prefix.");
    return res.status(401).json({success: false, message: "Unauthorized: Token not found."});
  }
  console.log("API Auth Middleware: Token extracted:", token ? "Present" : "MISSING_OR_EMPTY");

  if (!JWT_SECRET) { // from .env
    console.error("API Auth: JWT_SECRET is not configured. Cannot verify token.");
    return res.status(500).json({success: false, message: "Server error: Auth misconfiguration."});
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      id: decoded.userId,
      login: decoded.userLogin,
      displayName: decoded.displayName,
    };
    console.log(`API Auth Middleware: User ${req.user.login} successfully authenticated. Decoded:`, JSON.stringify(decoded));
    next();
  } catch (err) {
    console.warn("API Auth Middleware: JWT verification failed.", err.message, err.name);
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({success: false, message: "Unauthorized: Token expired."});
    }
    return res.status(401).json({success: false, message: "Unauthorized: Invalid token."});
  }
};

// API Routes
app.get("/api/bot/status", authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /status] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }

  try {
    // Ensure we have a valid Twitch token for this user
    try {
      await getValidTwitchTokenForUser(channelLogin);
      // Token is valid - proceed
    } catch (tokenError) {
      // Token refresh failed, but we can still check bot status
      console.warn(`[API /status] Token validation failed for ${channelLogin}, but continuing:`, tokenError.message);
    }

    const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
    const docSnap = await docRef.get();
    if (docSnap.exists && docSnap.data().isActive) {
      res.json({
        success: true,
        isActive: true,
        channelName: docSnap.data().channelName || channelLogin,
        needsReAuth: docSnap.data().needsTwitchReAuth === true,
      });
    } else {
      res.json({
        success: true,
        isActive: false,
        channelName: channelLogin,
        needsReAuth: docSnap.exists && docSnap.data().needsTwitchReAuth === true,
      });
    }
  } catch (error) {
    console.error(`[API /status] Error getting status for ${channelLogin}:`, error);
    res.status(500).json({success: false, message: "Error fetching bot status."});
  }
});

app.post("/api/bot/add", authenticateApiRequest, async (req, res) => {
  const {id: twitchUserId, login: channelLogin, displayName} = req.user;
  if (!db) {
    console.error("[API /add] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }

  // First check if we have valid Twitch tokens for this user
  try {
    await getValidTwitchTokenForUser(channelLogin);
    console.log(`[API /add] Verified valid Twitch token for ${channelLogin}`);
  } catch (tokenError) {
    console.error(`[API /add] Token validation failed for ${channelLogin}:`, tokenError.message);
    return res.status(403).json({
      success: false,
      needsReAuth: true,
      message: "Your Twitch authentication has expired. Please reconnect your account.",
    });
  }

  const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
  try {
    await docRef.set({
      channelName: channelLogin,
      twitchUserId: twitchUserId,
      displayName: displayName || channelLogin,
      isActive: true,
      addedBy: channelLogin,
      addedAt: FieldValue.serverTimestamp(),
      lastStatusChange: FieldValue.serverTimestamp(),
      // Mark as having valid auth
      needsTwitchReAuth: false,
    }, {merge: true});
    console.log(`[API /add] Bot activated for channel: ${channelLogin}`);
    res.json({success: true, message: `Bot has been requested for ${channelLogin}. It should join shortly!`});
  } catch (error) {
    console.error(`[API /add] Error activating bot for ${channelLogin}:`, error);
    res.status(500).json({success: false, message: "Error requesting bot."});
  }
});

app.post("/api/bot/remove", authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /remove] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }

  // Check authentication state, but don't block removal if token is invalid
  // We always want to allow users to remove the bot even if their auth has expired
  try {
    await getValidTwitchTokenForUser(channelLogin);
    console.log(`[API /remove] Verified valid Twitch token for ${channelLogin}`);
  } catch (tokenError) {
    // Log but continue - we'll allow removal even with expired tokens
    console.warn(`[API /remove] Token validation failed for ${channelLogin}, but continuing with removal:`, tokenError.message);
  }

  const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
  try {
    const docSnap = await docRef.get();
    if (docSnap.exists) {
      await docRef.update({
        isActive: false,
        lastStatusChange: FieldValue.serverTimestamp(),
      });
      console.log(`[API /remove] Bot deactivated for channel: ${channelLogin}`);
      res.json({success: true, message: `Bot has been requested to leave ${channelLogin}.`});
    } else {
      res.json({success: false, message: "Bot was not in your channel."});
    }
  } catch (error) {
    console.error(`[API /remove] Error deactivating bot for ${channelLogin}:`, error);
    res.status(500).json({success: false, message: "Error requesting bot removal."});
  }
});

// Logout Route
app.get("/auth/logout", (req, res) => {
  console.log("Logout requested. Client should clear its token.");
  res.redirect(FRONTEND_URL_CONFIG); // from .env
});

// API route to check auth status and refresh token if needed
app.get("/api/auth/status", authenticateApiRequest, async (req, res) => {
  const userLogin = req.user.login;
  console.log(`[API /auth/status] Checking auth status for ${userLogin}`);

  if (!db) {
    console.error("[API /auth/status] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }

  try {
    // Attempt to get a valid token, which will refresh if needed
    // Token is valid if this doesn't throw an error
    await getValidTwitchTokenForUser(userLogin);

    // If we get here, token is valid (either existing or refreshed)
    return res.json({
      success: true,
      isAuthenticated: true,
      needsReAuth: false,
      message: "Twitch authentication is valid.",
    });
  } catch (error) {
    console.error(`[API /auth/status] Error getting valid token for ${userLogin}:`, error.message);

    // Check if this is a critical auth error that requires re-auth
    const needsReAuth = error.message.includes("re-authenticate") ||
                         error.message.includes("Refresh token not available") ||
                         error.message.includes("User not found");

    // User exists and is authenticated with our app (JWT), but Twitch tokens are invalid
    return res.status(403).json({
      success: false,
      isAuthenticated: true, // JWT is valid, but Twitch tokens aren't
      needsReAuth: needsReAuth,
      message: needsReAuth ?
        "Twitch authentication required. Please re-authenticate with Twitch." :
        "Error validating Twitch authentication.",
    });
  }
});

// API route to force token refresh
app.post("/api/auth/refresh", authenticateApiRequest, async (req, res) => {
  const userLogin = req.user.login;
  console.log(`[API /auth/refresh] Manual token refresh requested for ${userLogin}`);

  if (!db) {
    console.error("[API /auth/refresh] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }

  try {
    // Clear any cached tokens to force a fresh refresh
    await clearCachedTokens(userLogin, "Manual refresh requested by user");

    // Try to get a fresh token
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userLogin);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      console.warn(`[API /auth/refresh] User document for ${userLogin} not found.`);
      return res.status(404).json({
        success: false,
        needsReAuth: true,
        message: "User not found. Please re-authenticate with Twitch.",
      });
    }

    const userData = userDoc.data();
    const {twitchRefreshToken} = userData;

    if (!twitchRefreshToken) {
      console.warn(`[API /auth/refresh] No refresh token found for ${userLogin}.`);
      return res.status(400).json({
        success: false,
        needsReAuth: true,
        message: "No refresh token available. Please re-authenticate with Twitch.",
      });
    }

    // Attempt to refresh the token
    const newTokens = await refreshTwitchToken(twitchRefreshToken);
    const newExpiresAt = new Date(Date.now() + newTokens.expiresIn * 1000);

    // Update the tokens in Firestore
    await userDocRef.update({
      twitchAccessToken: newTokens.accessToken,
      twitchRefreshToken: newTokens.refreshToken || twitchRefreshToken,
      twitchAccessTokenExpiresAt: newExpiresAt,
      lastTokenRefreshAt: FieldValue.serverTimestamp(),
      needsTwitchReAuth: false,
      lastTokenError: null,
      lastTokenErrorAt: null,
    });

    console.log(`[API /auth/refresh] Successfully refreshed token for ${userLogin}`);
    return res.json({
      success: true,
      message: "Twitch authentication refreshed successfully.",
    });
  } catch (error) {
    console.error(`[API /auth/refresh] Failed to refresh token for ${userLogin}:`, error.message);
    return res.status(401).json({
      success: false,
      needsReAuth: true,
      message: "Failed to refresh Twitch authentication. Please re-authenticate.",
      error: error.message,
    });
  }
});

// Helper to redirect to frontend with error parameters
const redirectToFrontendWithError = (res, error, errorDescription, state) => {
  const frontendErrorUrl = new URL(FRONTEND_URL_CONFIG);
  frontendErrorUrl.pathname = "/auth-error.html"; // Or your preferred error page
  if (error) frontendErrorUrl.searchParams.append("error", error);
  if (errorDescription) frontendErrorUrl.searchParams.append("error_description", errorDescription);
  if (state) frontendErrorUrl.searchParams.append("state", state); // Pass original state back if available
  console.warn(`Redirecting to frontend error page: ${frontendErrorUrl.toString()}`);
  return res.redirect(frontendErrorUrl.toString());
};

/**
 * Clears cached Twitch tokens for a user and marks them as requiring re-authentication
 * @param {string} userLogin - The Twitch channel/login name
 * @param {string} reason - Reason for clearing the tokens (for logging)
 * @return {Promise<boolean>} True if successful, false otherwise
 */
async function clearCachedTokens(userLogin, reason = "Unspecified reason") {
  if (!db) {
    console.error("[clearCachedTokens] Firestore (db) not initialized!");
    return false;
  }

  if (!userLogin) {
    console.error("[clearCachedTokens] No userLogin provided");
    return false;
  }

  try {
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userLogin);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      console.warn(`[clearCachedTokens] User document for ${userLogin} not found.`);
      return false;
    }

    await userDocRef.update({
      twitchAccessToken: null,
      twitchAccessTokenExpiresAt: null,
      needsTwitchReAuth: true,
      lastTokenError: reason,
      lastTokenErrorAt: FieldValue.serverTimestamp(),
    });

    console.log(`[clearCachedTokens] Successfully cleared tokens for ${userLogin}. Reason: ${reason}`);
    return true;
  } catch (error) {
    console.error(`[clearCachedTokens] Error clearing tokens for ${userLogin}:`, error.message);
    return false;
  }
}

/**
 * Refreshes a Twitch token using the refresh token with retry logic
 * @param {string} currentRefreshToken - The refresh token to use
 * @return {Promise<Object>} The new tokens and expiration
 */
async function refreshTwitchToken(currentRefreshToken) {
  if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET) {
    console.error("Twitch client ID or secret not configured for token refresh.");
    throw new Error("Server configuration error for Twitch token refresh.");
  }

  const MAX_RETRY_ATTEMPTS = 3;
  const RETRY_DELAY_MS = 5000; // 5 seconds between retries
  let lastError = null;

  for (let attempt = 1; attempt <= MAX_RETRY_ATTEMPTS; attempt++) {
    console.log(`Attempting to refresh Twitch token (Attempt ${attempt}/${MAX_RETRY_ATTEMPTS})`);
    try {
      const response = await axios.post(TWITCH_TOKEN_URL, null, {
        params: {
          grant_type: "refresh_token",
          refresh_token: currentRefreshToken,
          client_id: TWITCH_CLIENT_ID,
          client_secret: TWITCH_CLIENT_SECRET,
        },
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout: 15000, // 15 second timeout
      });

      if (response.status === 200 && response.data && response.data.access_token) {
        console.log(`Successfully refreshed Twitch token on attempt ${attempt}.`);
        return {
          accessToken: response.data.access_token,
          refreshToken: response.data.refresh_token || currentRefreshToken, // Twitch might issue a new refresh token or keep the old one
          expiresIn: response.data.expires_in,
        };
      } else {
        // Should not happen if status is 200, but treat as an error
        lastError = new Error(`Failed to fetch token, unexpected response structure. Status: ${response.status}`);
        console.warn(`Attempt ${attempt} failed: ${lastError.message}`);
      }
    } catch (error) {
      lastError = error;
      const errorDetails = {
        message: error.message,
        code: error.code || "UNKNOWN",
        status: error.response && error.response.status,
        responseData: error.response && error.response.data,
        attempt: `${attempt}/${MAX_RETRY_ATTEMPTS}`,
      };

      console.error(`[refreshTwitchToken] Error refreshing token on attempt ${attempt}:`,
        JSON.stringify(errorDetails, null, 2));

      // Determine if this error is retryable
      let isRetryable = false;

      if (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT") {
        // Timeout errors are retryable
        isRetryable = true;
        console.warn(`Attempt ${attempt} timed out. Will retry if attempts remain.`);
      } else if (error.response) {
        if (error.response.status >= 500) {
          // Server errors are retryable
          isRetryable = true;
          console.warn(`Attempt ${attempt} failed with server error ${error.response.status}. Will retry if attempts remain.`);
        } else if (error.response.status === 429) {
          // Rate limiting is retryable
          isRetryable = true;
          console.warn(`Attempt ${attempt} rate limited (429). Will retry after delay.`);
        } else if (error.response.status === 400 || error.response.status === 401 || error.response.status === 403) {
          // Auth errors are NOT retryable - likely a bad refresh token or client credentials
          console.warn(`Refresh token is likely invalid or revoked (${error.response.status}). User needs to re-authenticate.`);
          isRetryable = false;
        }
      } else if (error.request) {
        // Network errors with no response are retryable
        isRetryable = true;
        console.warn(`Attempt ${attempt} failed with network error. Will retry if attempts remain.`);
      }

      // If retryable and not the last attempt, wait and try again
      if (isRetryable && attempt < MAX_RETRY_ATTEMPTS) {
        console.info(`Waiting ${RETRY_DELAY_MS/1000} seconds before retry attempt ${attempt + 1}...`);
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
        continue;
      }

      // If not retryable or last attempt, break out
      break;
    }
  }

  // If we get here, all retries failed
  let finalErrorMessage = `Failed to refresh Twitch token after ${MAX_RETRY_ATTEMPTS} attempts.`;
  if (lastError) {
    if (lastError.response) {
      finalErrorMessage += ` Status: ${lastError.response.status}, Data: ${JSON.stringify(lastError.response.data)}`;
      if (lastError.response.status === 400 || lastError.response.status === 401 || lastError.response.status === 403) {
        finalErrorMessage += " User needs to re-authenticate or client credentials are invalid.";
      }
    } else {
      finalErrorMessage += ` Error: ${lastError.message}`;
    }
  }
  throw new Error(finalErrorMessage);
}

/**
 * Gets a valid Twitch access token for a user, refreshing if necessary
 * @param {string} userLogin - The user's login name
 * @return {Promise<string>} A valid access token
 */
async function getValidTwitchTokenForUser(userLogin) {
  if (!db) {
    console.error("[getValidTwitchTokenForUser] Firestore (db) not initialized!");
    throw new Error("Firestore not available.");
  }

  const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userLogin);
  const userDoc = await userDocRef.get();

  if (!userDoc.exists) {
    console.warn(`[getValidTwitchTokenForUser] User document for ${userLogin} not found.`);
    throw new Error("User not found or not authenticated with Twitch.");
  }

  const userData = userDoc.data();
  const {twitchAccessToken, twitchRefreshToken, twitchAccessTokenExpiresAt} = userData;

  // Token buffer - consider tokens invalid 5 minutes before actual expiry
  const TOKEN_EXPIRY_BUFFER_MS = 5 * 60 * 1000;

  // Check if token is valid for at least 5 more minutes
  if (twitchAccessToken && twitchAccessTokenExpiresAt) {
    // Handle both Firestore Timestamp objects and regular Date strings
    const expiryDate = typeof twitchAccessTokenExpiresAt.toDate === "function" ?
      twitchAccessTokenExpiresAt.toDate() :
      new Date(twitchAccessTokenExpiresAt);

    if (expiryDate > new Date(Date.now() + TOKEN_EXPIRY_BUFFER_MS)) {
      console.log(`[getValidTwitchTokenForUser] Using existing valid access token for ${userLogin}.`);
      return twitchAccessToken;
    }
  }

  if (!twitchRefreshToken) {
    console.warn(`[getValidTwitchTokenForUser] No refresh token found for ${userLogin}. Re-authentication required.`);
    throw new Error("Refresh token not available. User needs to re-authenticate.");
  }

  console.log(`[getValidTwitchTokenForUser] Access token for ${userLogin} expired or missing. Attempting refresh.`);
  try {
    const newTokens = await refreshTwitchToken(twitchRefreshToken);
    const newExpiresAt = new Date(Date.now() + newTokens.expiresIn * 1000);

    await userDocRef.update({
      twitchAccessToken: newTokens.accessToken,
      twitchRefreshToken: newTokens.refreshToken || twitchRefreshToken, // Update if a new one is provided
      twitchAccessTokenExpiresAt: newExpiresAt,
      lastTokenRefreshAt: FieldValue.serverTimestamp(),
      needsTwitchReAuth: false, // Clear any previous re-auth flags
    });
    console.log(`[getValidTwitchTokenForUser] Successfully refreshed and stored new tokens for ${userLogin}.`);
    return newTokens.accessToken;
  } catch (error) {
    console.error(`[getValidTwitchTokenForUser] Failed to refresh token for ${userLogin}:`, error.message);
    // If refresh fails, it might be due to revoked access or invalid refresh token
    try {
      await userDocRef.update({
        twitchAccessToken: null,
        twitchAccessTokenExpiresAt: null,
        needsTwitchReAuth: true,
        lastTokenError: error.message,
        lastTokenErrorAt: FieldValue.serverTimestamp(),
      });
      console.log(`[getValidTwitchTokenForUser] Marked tokens as invalid for ${userLogin}`);
    } catch (updateError) {
      console.error(`[getValidTwitchTokenForUser] Failed to update user document for ${userLogin}:`, updateError.message);
    }

    throw new Error("Failed to obtain a valid Twitch token. User may need to re-authenticate.");
  }
}

exports.webUi = functions.https.onRequest(app);
