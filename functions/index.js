/**
 * Twitch OAuth 2.0 Authentication and Bot Management API
 *
 * This Firebase Cloud Function provides Twitch OAuth authentication for users
 * who want to add the StreamSage bot to their Twitch channel. It implements
 * the full OAuth flow including token refresh, validation, and management.
 *
 * Key features:
 * - Complete Twitch OAuth 2.0 authentication flow
 * - Secure refresh token storage in Google Secret Manager
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
const {SecretManagerServiceClient} = require("@google-cloud/secret-manager");
let db;
let secretManagerClient;
try {
  db = new Firestore();
  secretManagerClient = new SecretManagerServiceClient();
  console.log("[CloudFunctions] Firestore and Secret Manager clients initialized.");
} catch (e) {
  console.error("[CloudFunctions] Client init error:", e);
}

// Helper to get GCP project ID for Secret Manager
function getProjectId() {
  const projectId = process.env.GCLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT;
  if (!projectId) {
    throw new Error("GCP project ID not found in environment variables.");
  }
  return projectId;
}


const CHANNELS_COLLECTION = "managedChannels";
const AUTO_CHAT_COLLECTION = "autoChatConfigs";

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
// For EventSub webhook creation for ad breaks (bot callback and shared secret)
const BOT_PUBLIC_URL = process.env.BOT_PUBLIC_URL || process.env.PUBLIC_URL; // fallback if shared naming
const TWITCH_EVENTSUB_SECRET = process.env.TWITCH_EVENTSUB_SECRET;
// Internal bot token is provided via a Secret Manager path in WEBUI_INTERNAL_TOKEN
let INTERNAL_BOT_TOKEN_VALUE = null;
async function getInternalBotTokenValue() {
  if (INTERNAL_BOT_TOKEN_VALUE) return INTERNAL_BOT_TOKEN_VALUE;
  const secretInput = process.env.WEBUI_INTERNAL_TOKEN;
  if (!secretInput) {
    throw new Error("WEBUI_INTERNAL_TOKEN is not configured (expected Secret Manager path)");
  }
  try {
    const name = normalizeSecretVersionPath(secretInput);
    const [version] = await secretManagerClient.accessSecretVersion({ name });
    INTERNAL_BOT_TOKEN_VALUE = version.payload.data.toString("utf8");
    if (!INTERNAL_BOT_TOKEN_VALUE) throw new Error("WEBUI_INTERNAL_TOKEN secret is empty");
    return INTERNAL_BOT_TOKEN_VALUE;
  } catch (e) {
    console.error("Failed to load WEBUI_INTERNAL_TOKEN from Secret Manager:", e.message);
    throw e;
  }
}
// Allow-list is defined strictly via Secret Manager path in ALLOWED_CHANNELS_SECRET_NAME
const ALLOWED_CHANNELS_SECRET_NAME = process.env.ALLOWED_CHANNELS_SECRET_NAME;

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
  const origin = req.headers.origin;

  // Build allowed origins list
  const allowedOrigins = new Set(["http://127.0.0.1:5002", "http://localhost:5002"]);
  if (FRONTEND_URL_CONFIG) {
    try {
      const url = new URL(FRONTEND_URL_CONFIG);
      allowedOrigins.add(`${url.protocol}//${url.host}`);
      // If using Firebase Hosting defaults, include both web.app and firebaseapp.com variants
      if (url.host.endsWith(".web.app")) {
        const altHost = url.host.replace(/\.web\.app$/, ".firebaseapp.com");
        allowedOrigins.add(`${url.protocol}//${altHost}`);
      } else if (url.host.endsWith(".firebaseapp.com")) {
        const altHost = url.host.replace(/\.firebaseapp\.com$/, ".web.app");
        allowedOrigins.add(`${url.protocol}//${altHost}`);
      }
    } catch (e) {
      console.warn("CORS: FRONTEND_URL is not a valid URL:", FRONTEND_URL_CONFIG);
    }
  } else {
    // If FRONTEND_URL not configured, be permissive to avoid breaking the UI, but echo the specific origin
    if (origin) allowedOrigins.add(origin);
  }

  console.log(`CORS Check: Origin: ${origin} | Allowed: ${Array.from(allowedOrigins).join(", ")}`);

  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

const TWITCH_AUTH_URL = "https://id.twitch.tv/oauth2/authorize";
const TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token";
const TWITCH_VALIDATE_URL = "https://id.twitch.tv/oauth2/validate";


// Normalize a Secret Manager reference to a Secret Version path
// Accepts:
// - full version path: projects/{project}/secrets/{secret}/versions/{version}
// - secret path without version: projects/{project}/secrets/{secret}
// - bare secret id: {secret}
// Returns a version path using "latest" when no version provided
function normalizeSecretVersionPath(secretInput) {
  if (!secretInput) return secretInput;
  if (secretInput.includes("/versions/")) return secretInput;
  if (secretInput.startsWith("projects/")) {
    return `${secretInput}/versions/latest`;
  }
  const projectId = getProjectId();
  return `projects/${projectId}/secrets/${secretInput}/versions/latest`;
}

// Load allow-listed channels strictly from the secret specified by ALLOWED_CHANNELS_SECRET_NAME.
// If the secret is missing or unreadable, deny all (no implicit fallbacks).
async function getAllowedChannelsList() {
  try {
    if (!ALLOWED_CHANNELS_SECRET_NAME) {
      console.error("[AllowList] ALLOWED_CHANNELS_SECRET_NAME is not set. Denying all by default.");
      return [];
    }
    const name = normalizeSecretVersionPath(ALLOWED_CHANNELS_SECRET_NAME);
    const [version] = await secretManagerClient.accessSecretVersion({ name });
    const secretCsv = version.payload.data.toString("utf8");
    const list = secretCsv
      .split(",")
      .map((c) => c.trim().toLowerCase())
      .filter(Boolean);
    console.log(`[AllowList] Loaded ${list.length} entries from ALLOWED_CHANNELS_SECRET_NAME.`);
    return list;
  } catch (e) {
    console.error("[AllowList] Error loading allow-list from Secret Manager:", e.message);
    // On error, deny all
    return [];
  }
}

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
    scope: "user:read:email channel:read:ads",
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
    const { access_token: accessToken, refresh_token: refreshToken } = tokenResponse.data;
    console.log("Access token and refresh token received from Twitch.");

    if (!accessToken || !refreshToken) {
      console.error("Missing access_token or refresh_token from Twitch.", tokenResponse.data);
      throw new Error("Twitch did not return the expected tokens.");
    }


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

      // Store tokens in Secret Manager and Firestore BEFORE redirecting
      if (!db) {
        console.error("Firestore (db) not initialized. Cannot store Twitch tokens.");
        return redirectToFrontendWithError(res, "token_store_failed", "Server configuration error: database unavailable.", twitchQueryState);
      }
      const userDocRef = db.collection(CHANNELS_COLLECTION).doc(twitchUser.login);
      try {
        // --- Secret Manager logic for refresh token ---
        const projectId = getProjectId();
        const secretId = `twitch-refresh-token-${twitchUser.id}`;
        let secretName = `projects/${projectId}/secrets/${secretId}`;
        let versionName;
        // Try to create the secret if it doesn't exist
        try {
          console.log(`[AuthCallback] Checking for secret existence: ${secretName}`);
          await secretManagerClient.getSecret({ name: secretName });
          console.log(`[AuthCallback] Secret already exists for user ${twitchUser.login}`);
        } catch (err) {
          if (err.code === 5) { // Not found
            console.log(`[AuthCallback] Secret not found. Creating secret: ${secretName}`);
            const [secret] = await secretManagerClient.createSecret({
              parent: `projects/${projectId}`,
              secretId,
              secret: { replication: { automatic: {} } },
            });
            secretName = secret.name;
            console.log(`[AuthCallback] Created new secret for user ${twitchUser.login}`);
          } else {
            throw err;
          }
        }
        // Always add a new version (rotate)
        const tokenBytes = Buffer.from(refreshToken || "", "utf8");
        console.log(`[AuthCallback] Adding secret version. parent=${secretName}, refreshToken.length=${refreshToken ? refreshToken.length : 0}, tokenBytesLength=${tokenBytes.length}`);
        const [version] = await secretManagerClient.addSecretVersion({
          parent: secretName,
          payload: { data: tokenBytes },
        });
        versionName = version.name;
        console.log(`[AuthCallback] Stored refresh token for ${twitchUser.login} in Secret Manager version ${versionName}`);

        await userDocRef.set({
          refreshTokenSecretPath: versionName, // Store the path to the secret version
          twitchUserId: twitchUser.id,
          displayName: twitchUser.displayName,
          lastLoginAt: FieldValue.serverTimestamp(),
          needsTwitchReAuth: false,
          lastTokenError: null,
          lastTokenErrorAt: null,
        }, {merge: true});
        console.log(`Twitch refresh token secret path stored for user ${twitchUser.login}`);

        // Now validate the tokens are working by attempting to use them
        try {
          await axios.get(TWITCH_VALIDATE_URL, {
            headers: { Authorization: `OAuth ${accessToken}` },
          });
          console.log(`Twitch tokens for ${twitchUser.login} successfully validated.`);
        } catch (validateError) {
          console.error(`Failed to validate new tokens for ${twitchUser.login}:`, validateError.message);
        }
      } catch (dbError) {
        console.error(`Error storing Twitch tokens for ${twitchUser.login}:`, dbError);
        return redirectToFrontendWithError(res, "token_store_failed", "Failed to securely store Twitch credentials. Please try again.", twitchQueryState);
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

  // Enforce allow-list if configured (check BEFORE token validation to return accurate errors)
  try {
    const allowedList = await getAllowedChannelsList();
    const isAllowed = allowedList.includes(channelLogin.toLowerCase());
    if (!isAllowed) {
      console.warn(`[API /add] Channel ${channelLogin} is not allow-listed. Rejecting self-serve activation.`);
      return res.status(403).json({
        success: false,
        code: "not_allowed",
        message: "This channel is not permitted to add the bot.",
        details: "Access to the cloud version of ChatSage is invite-only. If you'd like access, please contact the administrator via https://detekoi.github.io/#contact-me",
      });
    }
  } catch (allowErr) {
    console.error("[API /add] Error during allow-list check:", allowErr.message);
    return res.status(500).json({ success: false, message: "Server error during allow-list verification." });
  }

  // After allow-list passes, check if we have valid Twitch tokens for this user
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

// GET /api/commands - Fetch command states for the authenticated user's channel
app.get("/api/commands", authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /commands GET] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }

  try {
    // All available commands (matching the bot's command list)
    const ALL_COMMANDS = [
      { name: "help", aliases: ["commands"] },
      { name: "ping", aliases: [] },
      { name: "game", aliases: [] },
      { name: "ask", aliases: ["sage"] },
      { name: "search", aliases: [] },
      { name: "translate", aliases: [] },
      { name: "geo", aliases: [] },
      { name: "trivia", aliases: [] },
      { name: "riddle", aliases: [] },
      { name: "botlang", aliases: [] },
      { name: "lurk", aliases: [] },
    ];

    // Fetch disabled commands for this channel
    const docRef = db.collection("channelCommands").doc(channelLogin);
    const docSnap = await docRef.get();
    const disabledCommands = docSnap.exists && docSnap.data().disabledCommands ? docSnap.data().disabledCommands : [];

    // Build response with command status
    const commands = ALL_COMMANDS.map(cmd => ({
      name: cmd.aliases.length > 0 ? `${cmd.name} (${cmd.aliases.map(a => `!${a}`).join(", ")})` : cmd.name,
      primaryName: cmd.name,
      enabled: !disabledCommands.includes(cmd.name),
    }));

    console.log(`[API /commands GET] Retrieved command states for ${channelLogin}: ${disabledCommands.length} disabled commands`);
    res.json({
      success: true,
      commands: commands,
    });
  } catch (error) {
    console.error(`[API /commands GET] Error fetching command states for ${channelLogin}:`, error);
    res.status(500).json({success: false, message: "Error fetching command settings."});
  }
});

// --- Auto-Chat Settings API ---
app.get("/api/auto-chat", authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /auto-chat GET] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }
  try {
    const docRef = db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin);
    const snap = await docRef.get();
    const defaultCfg = { mode: "off", categories: { greetings: true, facts: true, questions: true, ads: false } };
    const cfg = snap.exists ? { ...defaultCfg, ...snap.data() } : defaultCfg;
    return res.json({ success: true, config: {
      mode: (cfg.mode || "off"),
      categories: {
        greetings: cfg.categories && cfg.categories.greetings !== false,
        facts: cfg.categories && cfg.categories.facts !== false,
        questions: cfg.categories && cfg.categories.questions !== false,
        ads: cfg.categories && cfg.categories.ads === true,
      },
    }});
  } catch (err) {
    console.error("[API /auto-chat GET] Error:", err);
    return res.status(500).json({ success: false, message: "Failed to load auto-chat config." });
  }
});

app.post("/api/auto-chat", authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /auto-chat POST] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }
  try {
    const body = req.body || {};
    const mode = (body.mode || "").toLowerCase();
    const validModes = ["off","low","medium","high"];
    if (mode && !validModes.includes(mode)) {
      return res.status(400).json({ success: false, message: "Invalid mode." });
    }
    const categories = body.categories && typeof body.categories === "object" ? body.categories : {};
    const updates = {};
    if (mode) updates.mode = mode;
    updates.categories = {
      greetings: categories.greetings !== false,
      facts: categories.facts !== false,
      questions: categories.questions !== false,
      ads: categories.ads === true,
    };
    updates.channelName = channelLogin;
    updates.updatedAt = new Date();
    await db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin).set(updates, { merge: true });
    
    // Reconcile ad-break EventSub subscription immediately when setting changes
    try {
      if (typeof updates.categories?.ads === "boolean") {
        await ensureAdBreakSubscription(channelLogin, updates.categories.ads);
      }
    } catch (subErr) {
      console.warn(`[API /auto-chat POST] ensureAdBreakSubscription warning for ${channelLogin}:`, subErr.message);
      // Do not fail the save; UI will still be updated. Admins can retry.
    }
    return res.json({ success: true, config: updates });
  } catch (err) {
    console.error("[API /auto-chat POST] Error:", err);
    return res.status(500).json({ success: false, message: "Failed to save auto-chat config." });
  }
});

// Helper in web UI backend to call the bot to ensure ad-break EventSub subscriptions
async function ensureAdBreakSubscription(channelLogin, adsEnabled) {
  if (!BOT_PUBLIC_URL) {
    // If the bot public URL is not set here, the bot process itself will reconcile via Firestore listener.
    return;
  }
  try {
    // Acquire a valid broadcaster user token (has channel:read:ads scope after re-auth)
    const accessToken = await getValidTwitchTokenForUser(channelLogin);
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
    const userDoc = await userDocRef.get();
    const userId = userDoc.exists ? userDoc.data().twitchUserId : null;
    if (!userId) return;

    const HELIX_URL = "https://api.twitch.tv/helix";
    const headers = {
      Authorization: `Bearer ${accessToken}`,
      "Client-ID": TWITCH_CLIENT_ID,
      "Content-Type": "application/json",
    };

    // List current subs for this broadcaster/type
    const list = await axios.get(`${HELIX_URL}/eventsub/subscriptions`, { headers });
    const existing = (list.data && list.data.data ? list.data.data : []).filter(
      (s) => s.type === "channel.ad_break.begin" && s.condition?.broadcaster_user_id === String(userId),
    );

    if (adsEnabled) {
      if (existing.length > 0) return; // already subscribed
      const body = {
        type: "channel.ad_break.begin",
        version: "1",
        condition: { broadcaster_user_id: String(userId) },
        transport: {
          method: "webhook",
          callback: `${BOT_PUBLIC_URL}/twitch/event`,
          secret: TWITCH_EVENTSUB_SECRET,
        },
      };
      await axios.post(`${HELIX_URL}/eventsub/subscriptions`, body, { headers });
      return;
    } else {
      // Delete existing
      for (const sub of existing) {
        await axios.delete(`${HELIX_URL}/eventsub/subscriptions`, {
          headers,
          params: { id: sub.id },
        });
      }
      return;
    }
  } catch (e) {
    throw e;
  }
}

// Expose ad schedule to the bot (uses broadcaster user token with channel:read:ads)
// Removed less-secure public schedule route. Only internal route is available.

// Internal bot-only route (uses INTERNAL_BOT_TOKEN). Requires ?channel=
app.get("/internal/ads/schedule", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const expected = await getInternalBotTokenValue();
    if (!token || token !== expected) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    const channelLogin = (req.query.channel || '').toString().toLowerCase();
    if (!channelLogin) return res.status(400).json({ success: false, message: "Missing channel parameter" });
    if (!db) return res.status(500).json({ success: false, message: "Firestore not available." });
    const accessToken = await getValidTwitchTokenForUser(channelLogin);
    const userDoc = await db.collection(CHANNELS_COLLECTION).doc(channelLogin).get();
    const userId = userDoc.exists ? userDoc.data().twitchUserId : null;
    if (!userId) return res.status(404).json({ success: false, message: "User not found" });
    const response = await axios.get("https://api.twitch.tv/helix/channels/ads", {
      headers: { Authorization: `Bearer ${accessToken}`, "Client-ID": TWITCH_CLIENT_ID },
      params: { broadcaster_id: String(userId) },
      timeout: 15000,
    });
    return res.json({ success: true, data: response.data });
  } catch (e) {
    return res.status(400).json({ success: false, message: e.message });
  }
});

// POST /api/commands - Toggle command state for the authenticated user's channel
app.post("/api/commands", authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  const { command, enabled } = req.body;

  if (!db) {
    console.error("[API /commands POST] Firestore (db) not initialized!");
    return res.status(500).json({success: false, message: "Firestore not available."});
  }

  if (!command || typeof enabled !== "boolean") {
    return res.status(400).json({success: false, message: "Invalid request body. 'command' and 'enabled' are required."});
  }

  // Validate command name
  const validCommands = ["help", "ping", "game", "ask", "search", "translate", "geo", "trivia", "riddle", "botlang", "lurk"];
  if (!validCommands.includes(command)) {
    return res.status(400).json({success: false, message: "Invalid command name."});
  }

  // Prevent disabling critical commands
  if (command === "help" && !enabled) {
    return res.status(400).json({success: false, message: "The help command cannot be disabled."});
  }

  try {
    const docRef = db.collection("channelCommands").doc(channelLogin);
    
    if (enabled) {
      // Enable command by removing from disabled list
      await docRef.set({ 
        disabledCommands: FieldValue.arrayRemove(command),
        channelName: channelLogin, 
      }, { merge: true });
    } else {
      // Disable command by adding to disabled list
      await docRef.set({ 
        disabledCommands: FieldValue.arrayUnion(command),
        channelName: channelLogin, 
      }, { merge: true });
    }

    console.log(`[API /commands POST] Command '${command}' ${enabled ? "enabled" : "disabled"} for ${channelLogin}`);
    res.json({
      success: true,
      message: `Command '${command}' ${enabled ? "enabled" : "disabled"} successfully.`,
    });
  } catch (error) {
    console.error(`[API /commands POST] Error toggling command '${command}' for ${channelLogin}:`, error);
    res.status(500).json({success: false, message: "Error updating command settings."});
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
    const {refreshTokenSecretPath} = userData;
    if (!refreshTokenSecretPath) {
      console.warn(`[API /auth/refresh] No refresh token secret path found for ${userLogin}.`);
      return res.status(400).json({
        success: false,
        needsReAuth: true,
        message: "No refresh token available. Please re-authenticate with Twitch.",
      });
    }
    // Fetch refresh token from Secret Manager
    const [version] = await secretManagerClient.accessSecretVersion({ name: refreshTokenSecretPath });
    const twitchRefreshToken = version.payload.data.toString("utf8");
    // Attempt to refresh the token
    await refreshTwitchToken(twitchRefreshToken);
    // Update the refresh status in Firestore (no longer storing access tokens)
    await userDocRef.update({
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
  const {refreshTokenSecretPath} = userData;
  // No longer storing access tokens - always refresh from the refresh token
  if (!refreshTokenSecretPath) {
    console.warn(`[getValidTwitchTokenForUser] No refresh token secret path found for ${userLogin}. Re-authentication required.`);
    throw new Error("Refresh token not available. User needs to re-authenticate.");
  }
  console.log(`[getValidTwitchTokenForUser] Refreshing access token for ${userLogin} from refresh token.`);
  try {
    // Fetch refresh token from Secret Manager
    const [version] = await secretManagerClient.accessSecretVersion({ name: refreshTokenSecretPath });
    const currentRefreshToken = version.payload.data.toString("utf8");
    const newTokens = await refreshTwitchToken(currentRefreshToken);
    await userDocRef.update({
      lastTokenRefreshAt: FieldValue.serverTimestamp(),
      needsTwitchReAuth: false,
    });
    console.log(`[getValidTwitchTokenForUser] Successfully refreshed access token for ${userLogin}.`);
    return newTokens.accessToken;
  } catch (error) {
    console.error(`[getValidTwitchTokenForUser] Failed to refresh token for ${userLogin}:`, error.message);
    try {
      await userDocRef.update({
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
