const express = require("express");
const functions = require("firebase-functions");
const axios = require("axios");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const validator = require("validator");
const { Firestore, FieldValue } = require("@google-cloud/firestore");
const { SecretManagerServiceClient } = require("@google-cloud/secret-manager");

const app = express();

// Trust proxy headers from Cloud Run/Firebase Hosting
app.set("trust proxy", true);

app.use(express.json());
app.use(cookieParser());

const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID;
const TWITCH_CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET;

const CALLBACK_REDIRECT_URI_CONFIG = process.env.CALLBACK_URL;
const FRONTEND_URL_CONFIG = process.env.FRONTEND_URL;

const TWITCH_TOKEN_URL = "https://id.twitch.tv/oauth2/token";
const TWITCH_VALIDATE_URL = "https://id.twitch.tv/oauth2/validate";

const JWT_SECRET = process.env.JWT_SECRET_KEY;

const CHANNELS_COLLECTION = "managedChannels";
const AUTO_CHAT_COLLECTION = "autoChatConfigs";

const WEBUI_INTERNAL_TOKEN = process.env.WEBUI_INTERNAL_TOKEN;
const ALLOWED_CHANNELS_SECRET_NAME = process.env.ALLOWED_CHANNELS_SECRET_NAME;
const BOT_PUBLIC_URL = process.env.BOT_PUBLIC_URL;
const TWITCH_EVENTSUB_SECRET = process.env.TWITCH_EVENTSUB_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const TWITCH_BOT_USERNAME = process.env.TWITCH_BOT_USERNAME || "";

let db;
let secretManagerClient;

// In-memory token cache to avoid unnecessary refreshes
const tokenCache = new Map(); // userLogin -> { token, expiresAt }
try {
  db = new Firestore();
  secretManagerClient = new SecretManagerServiceClient();
  console.log("Firestore and Secret Manager initialized successfully.");
} catch (initError) {
  console.error("Failed to initialize Firestore or Secret Manager:", initError);
}

// Input sanitization helper
function sanitizeUsername(username) {
  if (!username || typeof username !== "string") {
    throw new Error("Invalid username");
  }
  const trimmed = username.trim().toLowerCase();
  // Twitch usernames: 4-25 characters, alphanumeric + underscore
  if (!validator.isAlphanumeric(trimmed.replace(/_/g, "")) || trimmed.length < 4 || trimmed.length > 25) {
    throw new Error("Invalid username format");
  }
  return validator.escape(trimmed);
}

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: "Too many authentication attempts, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // Limit each IP to 60 requests per minute
  message: "Too many requests, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

function getProjectId() {
  const projectId = process.env.GCLOUD_PROJECT || process.env.GCP_PROJECT || process.env.GOOGLE_CLOUD_PROJECT;
  if (!projectId) {
    throw new Error("GCP project ID not found in environment variables");
  }
  return projectId;
}

function normalizeSecretVersionPath(secretInput) {
  if (!secretInput) throw new Error("secretInput is empty");
  if (secretInput.includes("/versions/")) return secretInput;
  return `${secretInput}/versions/latest`;
}

async function getInternalBotTokenValue() {
  const secretInput = WEBUI_INTERNAL_TOKEN;
  if (!secretInput) {
    throw new Error("WEBUI_INTERNAL_TOKEN is not configured (expected Secret Manager path)");
  }
  try {
    const name = normalizeSecretVersionPath(secretInput);
    const [version] = await secretManagerClient.accessSecretVersion({ name });
    return version.payload.data.toString("utf8");
  } catch (error) {
    console.error("Error fetching WEBUI_INTERNAL_TOKEN from Secret Manager:", error.message);
    throw new Error("Failed to fetch internal bot token.");
  }
}

function redirectToFrontendWithError(res, errorCode, errorMessage, twitchQueryState) {
  let errorUrl;
  try {
    errorUrl = new URL("/auth-error.html", FRONTEND_URL_CONFIG);
    errorUrl.searchParams.set("error", errorCode);
    errorUrl.searchParams.set("error_description", errorMessage);
    if (twitchQueryState) {
      try {
        const parsedState = JSON.parse(twitchQueryState);
        if (parsedState.frontendRedirect) {
          errorUrl.searchParams.set("frontendRedirect", parsedState.frontendRedirect);
        }
      } catch {
        // Ignore parse error
      }
    }
  } catch (urlError) {
    console.error("Error constructing error redirect URL:", urlError);
    return res.status(500).send("Authentication failed and unable to construct error redirect.");
  }
  console.error(`Redirecting to error page: ${errorUrl.toString()}`);
  return res.redirect(errorUrl.toString());
}

function buildTwitchAuthUrl(currentTwitchClientId, currentCallbackRedirectUri, state) {
  const authUrl = new URL("https://id.twitch.tv/oauth2/authorize");
  authUrl.searchParams.set("client_id", currentTwitchClientId);
  authUrl.searchParams.set("redirect_uri", currentCallbackRedirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "user:read:email channel:read:ads channel:manage:moderators");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("force_verify", "true");
  return authUrl;
}

// CORS config
const allowedOriginsSet = (() => {
  const allowedOrigins = new Set(["http://127.0.0.1:5002", "http://localhost:5002"]);
  if (FRONTEND_URL_CONFIG) {
    try {
      const url = new URL(FRONTEND_URL_CONFIG);
      allowedOrigins.add(`${url.protocol}//${url.host}`);
    } catch {
      // Ignore parse error
    }
  }
  return allowedOrigins;
})();

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOriginsSet.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  
  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  
  // Content Security Policy
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://app.rybbit.io; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://api.wildcat.chat https://api.twitch.tv; frame-ancestors 'none';",
  );
  
  if (IS_PRODUCTION) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }
  
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

app.get("/", (req, res) => {
  res.send("Web UI Cloud Function is running!");
});

app.get("/test/env", (req, res) => {
  res.json({
    twitchClientId: TWITCH_CLIENT_ID ? "Set" : "Not Set",
    twitchClientSecret: TWITCH_CLIENT_SECRET ? "Set" : "Not Set",
    callbackRedirectUri: CALLBACK_REDIRECT_URI_CONFIG || "Not Set",
    frontendUrl: FRONTEND_URL_CONFIG || "Not Set",
    jwtSecret: JWT_SECRET ? "Set" : "Not Set",
    webuiInternalToken: WEBUI_INTERNAL_TOKEN ? "Set" : "Not Set",
    allowedChannelsSecretName: ALLOWED_CHANNELS_SECRET_NAME || "Not Set",
    botPublicUrl: BOT_PUBLIC_URL || "Not Set",
    twitchEventsubSecret: TWITCH_EVENTSUB_SECRET ? "Set" : "Not Set",
  });
});

async function getAllowedChannelsList() {
  try {
    if (!ALLOWED_CHANNELS_SECRET_NAME) {
      console.error("[AllowList] ALLOWED_CHANNELS_SECRET_NAME is not set. Denying all by default.");
      return [];
    }
    const name = normalizeSecretVersionPath(ALLOWED_CHANNELS_SECRET_NAME);
    const [version] = await secretManagerClient.accessSecretVersion({ name });
    const csvData = version.payload.data.toString("utf8").trim();
    if (!csvData) {
      console.warn("[AllowList] Secret content is empty. Denying all by default.");
      return [];
    }
    const channels = csvData.split(",").map(ch => ch.trim().toLowerCase()).filter(Boolean);
    console.log(`[AllowList] Loaded ${channels.length} allowed channels from Secret Manager.`);
    return channels;
  } catch (error) {
    console.error("[AllowList] Error fetching allowed channels from Secret Manager:", error.message);
    return [];
  }
}

app.get("/auth/twitch", authLimiter, async (req, res) => {
  console.log("--- /auth/twitch HIT ---");
  const frontendRedirect = req.query.redirect || "/";
  const state = JSON.stringify({
    frontendRedirect: frontendRedirect,
    nonce: crypto.randomBytes(16).toString("hex"),
  });
  console.log("Generated state for OAuth:", state);
  console.log("Callback redirect URI used for state generation:", CALLBACK_REDIRECT_URI_CONFIG);
  const authUrl = buildTwitchAuthUrl(TWITCH_CLIENT_ID, CALLBACK_REDIRECT_URI_CONFIG, state);
  console.log("Redirecting user to Twitch auth URL:", authUrl.toString());
  res.redirect(authUrl.toString());
});

app.get("/auth/twitch/callback", authLimiter, async (req, res) => {
  console.log("--- /auth/twitch/callback HIT ---");
  console.log("Callback Request Query Params:", JSON.stringify(req.query));
  const { code, state: twitchQueryState, error: twitchError, error_description: twitchErrorDescription } = req.query;

  if (twitchError) {
    console.error(`Twitch OAuth explicit error: ${twitchError} - ${twitchErrorDescription}`);
    return redirectToFrontendWithError(res, twitchError, twitchErrorDescription, twitchQueryState);
  }

  // Validate state parameter (CSRF protection)
  if (!twitchQueryState) {
    console.error("[OAuth] Missing state parameter in callback");
    return redirectToFrontendWithError(res, "invalid_request", "Missing state parameter", null);
  }

  let parsedState;
  try {
    parsedState = JSON.parse(twitchQueryState);
    if (!parsedState.nonce || !parsedState.frontendRedirect) {
      throw new Error("Invalid state structure");
    }
    console.log("[OAuth] State validated successfully:", { nonce: parsedState.nonce.substring(0, 8) + "..." });
  } catch (stateError) {
    console.error("[OAuth] State validation failed:", stateError.message);
    return redirectToFrontendWithError(res, "invalid_state", "State validation failed - possible CSRF attack", twitchQueryState);
  }
  try {
    console.log("Exchanging code for token. Callback redirect_uri used for exchange:", CALLBACK_REDIRECT_URI_CONFIG);
    const tokenResponse = await axios.post(
      TWITCH_TOKEN_URL,
      null,
      {
        params: {
          client_id: TWITCH_CLIENT_ID,
          client_secret: TWITCH_CLIENT_SECRET,
          code: code,
          grant_type: "authorization_code",
          redirect_uri: CALLBACK_REDIRECT_URI_CONFIG,
        },
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        timeout: 15000,
      },
    );
    console.log("Token exchange successful. Validating token and fetching user info...");
    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;
    if (!accessToken || !refreshToken) {
      throw new Error("Missing access or refresh token from Twitch.");
    }
    await axios.get(TWITCH_VALIDATE_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
      timeout: 15000,
    });
    console.log("Token validated. Fetching Twitch user info...");
    const userResponse = await axios.get("https://api.twitch.tv/helix/users", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Client-ID": TWITCH_CLIENT_ID,
      },
      timeout: 15000,
    });
    const twitchUserData = userResponse.data && userResponse.data.data && userResponse.data.data[0];
    if (twitchUserData) {
      const twitchUser = {
        id: twitchUserData.id,
        login: twitchUserData.login,
        displayName: twitchUserData.display_name,
        email: twitchUserData.email,
      };
      console.log("Twitch user fetched successfully:", twitchUser.login);
      const userDocRef = db.collection(CHANNELS_COLLECTION).doc(twitchUser.login);
      const jwtPayload = {
        login: twitchUser.login,
        userId: twitchUser.id,
        displayName: twitchUser.displayName,
        email: twitchUser.email || null,
      };
      const sessionToken = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: "7d" });
      console.log("JWT session token generated for user:", twitchUser.login);
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
          email: twitchUser.email || null, // Store user email from OAuth
          lastLoginAt: FieldValue.serverTimestamp(),
          needsTwitchReAuth: false,
          lastTokenError: null,
          lastTokenErrorAt: null,
        }, {merge: true});
        console.log(`Twitch refresh token secret path stored for user ${twitchUser.login}`);

        // Now validate the tokens are working by attempting to use them
        try {
          await axios.get(TWITCH_VALIDATE_URL, {
            headers: { Authorization: `Bearer ${accessToken}` },
          });
          console.log(`Twitch tokens for ${twitchUser.login} successfully validated.`);
        } catch (validateError) {
          console.error(`Failed to validate new tokens for ${twitchUser.login}:`, validateError.message);
        }
      } catch (dbError) {
        console.error(`Error storing Twitch tokens for ${twitchUser.login}:`, dbError);
        return redirectToFrontendWithError(res, "token_store_failed", "Failed to securely store Twitch credentials. Please try again.", twitchQueryState);
      }

      // Token storage successful
      // Note: Due to cross-origin limitations (Firebase Hosting vs Cloud Run),
      // we send the token in URL for the client to store. This is a known limitation
      // of the current architecture. For same-domain setup, use HTTP-only cookies instead.
      
      const frontendAuthCompleteUrl = new URL(FRONTEND_URL_CONFIG);
      frontendAuthCompleteUrl.pathname = "/auth-complete.html";
      frontendAuthCompleteUrl.searchParams.append("user_login", twitchUser.login);
      frontendAuthCompleteUrl.searchParams.append("user_id", twitchUser.id);
      frontendAuthCompleteUrl.searchParams.append("state", twitchQueryState);
      frontendAuthCompleteUrl.searchParams.append("session_token", sessionToken);

      console.log(`Redirecting to frontend auth-complete page: ${frontendAuthCompleteUrl.toString()}`);
      return res.redirect(frontendAuthCompleteUrl.toString());
    } else {
      console.error("Failed to validate token or get user info from Twitch after token exchange.");
      throw new Error("Failed to validate token or get user info from Twitch.");
    }
  } catch (error) {
    console.error("[AuthCallback] Twitch OAuth callback error:", error.response ? JSON.stringify(error.response.data, null, 2) : error.message, error.stack);
    return redirectToFrontendWithError(res, "auth_failed", "Authentication failed with Twitch due to an internal server error.", twitchQueryState);
  }
});

const authenticateApiRequest = (req, res, next) => {
  // Due to cross-origin setup (Firebase Hosting + Cloud Run), we primarily use Authorization header
  // Cookie-based auth would work for same-domain deployments
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  
  if (!token) {
    console.error("[authenticateApiRequest] No token provided in Authorization header.");
    return res.status(401).json({ success: false, message: "Unauthorized: Missing token." });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Validate required fields
    if (!decoded.login || !decoded.userId) {
      throw new Error("Invalid token payload");
    }
    
    req.user = {
      login: sanitizeUsername(decoded.login),
      userId: decoded.userId,
      displayName: decoded.displayName,
      email: decoded.email || null,
    };
    console.log(`[authenticateApiRequest] User authenticated: ${req.user.login}`);
    next();
  } catch (err) {
    console.error("[authenticateApiRequest] Token verification failed:", err.message);
    return res.status(401).json({ success: false, message: "Unauthorized: Invalid token." });
  }
};

app.get("/api/bot/status", apiLimiter, authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /status] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    try {
      await getValidTwitchTokenForUser(channelLogin);
    } catch (tokenError) {
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
    res.status(500).json({ success: false, message: "Error fetching bot status." });
  }
});

app.post("/api/bot/add", apiLimiter, authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /add] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    const allowedList = await getAllowedChannelsList();
    const isAllowed = allowedList.includes(channelLogin.toLowerCase());
    if (!isAllowed) {
      console.warn(`[API /add] Channel ${channelLogin} is not on the allow-list.`);
      return res.status(403).json({
        success: false,
        message: "Your channel is not on the allow-list. Contact support for access.",
      });
    }
  } catch (error) {
    console.error(`[API /add] Error checking allow-list for ${channelLogin}:`, error);
    return res.status(500).json({
      success: false,
      message: "Error verifying channel access. Please try again later.",
    });
  }
  try {
    await getValidTwitchTokenForUser(channelLogin);
    console.log(`[API /add] Verified valid Twitch token for ${channelLogin}`);
  } catch (tokenError) {
    console.error(`[API /add] Token validation failed for ${channelLogin}:`, tokenError.message);
    return res.status(403).json({
      success: false,
      message: "Twitch authentication required. Please re-authenticate with Twitch.",
    });
  }
  const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
  const broadcasterUserId = req.user.userId;
  
  try {
    await docRef.set({
      channelName: channelLogin,
      isActive: true,
      addedAt: FieldValue.serverTimestamp(),
      twitchUserId: broadcasterUserId, // Ensure twitchUserId is stored
    }, { merge: true });
    console.log(`Channel ${channelLogin} activated successfully.`);

    // Automatically add bot as moderator
    let modStatus = { success: false, error: "Bot username not configured" };
    if (TWITCH_BOT_USERNAME) {
      try {
        console.log(`[API /add] Attempting to add bot ${TWITCH_BOT_USERNAME} as moderator...`);
        const botUserId = await getUserIdFromUsername(TWITCH_BOT_USERNAME);
        
        if (botUserId) {
          modStatus = await addModerator(channelLogin, broadcasterUserId, botUserId);
          if (modStatus.success) {
            console.log(`[API /add] Bot successfully added as moderator to ${channelLogin}`);
          } else {
            console.warn(`[API /add] Failed to add bot as moderator: ${modStatus.error}`);
          }
        } else {
          console.warn(`[API /add] Could not find user ID for bot username: ${TWITCH_BOT_USERNAME}`);
          modStatus = { success: false, error: "Bot user not found" };
        }
      } catch (modError) {
        console.error("[API /add] Error adding bot as moderator:", modError);
        modStatus = { success: false, error: modError.message };
      }
    } else {
      console.warn("[API /add] TWITCH_BOT_USERNAME not configured, skipping moderator setup");
    }

    res.json({
      success: true,
      message: `Bot successfully added to ${channelLogin}.`,
      moderatorStatus: modStatus.success ? "added" : "failed",
      moderatorError: modStatus.success ? undefined : modStatus.error,
    });
  } catch (error) {
    console.error(`[API /add] Error adding channel ${channelLogin}:`, error);
    res.status(500).json({ success: false, message: "Failed to add bot. Please try again." });
  }
});

app.post("/api/bot/remove", apiLimiter, authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /remove] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    await getValidTwitchTokenForUser(channelLogin);
    console.log(`[API /remove] Verified valid Twitch token for ${channelLogin}`);
  } catch (tokenError) {
    console.warn(`[API /remove] Token validation failed for ${channelLogin}, but allowing removal:`, tokenError.message);
  }
  const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
  try {
    const docSnap = await docRef.get();
    if (docSnap.exists) {
      await docRef.update({ isActive: false, removedAt: FieldValue.serverTimestamp() });
      console.log(`Channel ${channelLogin} deactivated successfully.`);
      res.json({ success: true, message: `Bot successfully removed from ${channelLogin}.` });
    } else {
      console.warn(`[API /remove] No document found for ${channelLogin}`);
      res.json({ success: true, message: `No active bot found for ${channelLogin}.` });
    }
  } catch (error) {
    console.error(`[API /remove] Error removing channel ${channelLogin}:`, error);
    res.status(500).json({ success: false, message: "Failed to remove bot. Please try again." });
  }
});

app.get("/api/commands", apiLimiter, authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /commands GET] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    const ALL_COMMANDS = [
      "ask", "search", "game", "translate", "help", "lurk",
      "geo", "riddle", "trivia",
      "botlang", "auto", "disable", "enable", "ping",
    ];
    const docRef = db.collection("channelCommands").doc(channelLogin);
    const snap = await docRef.get();
    const data = snap.exists ? snap.data() : {};
    const disabledCommands = data.disabledCommands || [];
    
    const commandSettings = ALL_COMMANDS.map(cmd => ({
      primaryName: cmd,
      name: cmd,
      enabled: !disabledCommands.includes(cmd),
    }));
    return res.json({ success: true, commands: commandSettings });
  } catch (err) {
    console.error("[API /commands GET] Error:", err);
    return res.status(500).json({ success: false, message: "Error fetching command settings." });
  }
});

app.post("/api/commands", apiLimiter, authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /commands POST] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    const { command, enabled } = req.body;
    if (!command || typeof enabled !== "boolean") {
      return res.status(400).json({ success: false, message: "Invalid command or enabled value." });
    }
    
    const docRef = db.collection("channelCommands").doc(channelLogin);
    
    // Use array operations to match bot's expected structure
    if (enabled) {
      // Enable command by removing from disabledCommands array
      await docRef.set({ 
        disabledCommands: FieldValue.arrayRemove(command),
        channelName: channelLogin,
      }, { merge: true });
      console.log(`[API /commands POST] Enabled ${command} for ${channelLogin} (removed from disabledCommands)`);
    } else {
      // Disable command by adding to disabledCommands array
      await docRef.set({ 
        disabledCommands: FieldValue.arrayUnion(command),
        channelName: channelLogin,
      }, { merge: true });
      console.log(`[API /commands POST] Disabled ${command} for ${channelLogin} (added to disabledCommands)`);
    }
    
    return res.json({ success: true, message: `Command ${command} ${enabled ? "enabled" : "disabled"} successfully.` });
  } catch (err) {
    console.error("[API /commands POST] Error:", err);
    return res.status(500).json({ success: false, message: "Error updating command settings." });
  }
});

app.get("/api/auto-chat", apiLimiter, authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /auto-chat GET] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    const docRef = db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin);
    const snap = await docRef.get();
    const defaultCfg = { mode: "off", categories: { greetings: true, facts: true, questions: true, celebrations: true, ads: false } };
    const cfg = snap.exists ? { ...defaultCfg, ...snap.data() } : defaultCfg;
    return res.json({
      success: true, config: {
        mode: (cfg.mode || "off"),
        categories: {
          greetings: cfg.categories && cfg.categories.greetings !== false,
          facts: cfg.categories && cfg.categories.facts !== false,
          questions: cfg.categories && cfg.categories.questions !== false,
          celebrations: cfg.categories && cfg.categories.celebrations !== false,
          ads: cfg.categories && cfg.categories.ads === true,
        },
      },
    });
  } catch (err) {
    console.error("[API /auto-chat GET] Error:", err);
    return res.status(500).json({ success: false, message: "Failed to load auto-chat config." });
  }
});

app.post("/api/auto-chat", apiLimiter, authenticateApiRequest, async (req, res) => {
  const channelLogin = req.user.login;
  if (!db) {
    console.error("[API /auto-chat POST] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    const body = req.body || {};
    const mode = (body.mode || "").toLowerCase();
    const validModes = ["off", "low", "medium", "high"];
    if (mode && !validModes.includes(mode)) {
      return res.status(400).json({ success: false, message: "Invalid mode." });
    }
    const categories = body.categories && typeof body.categories === "object" ? body.categories : {};
    const updates = {};
    // Default to "off" if mode is not provided or invalid
    updates.mode = mode && validModes.includes(mode) ? mode : "off";
    updates.categories = {
      greetings: categories.greetings !== false,
      facts: categories.facts !== false,
      questions: categories.questions !== false,
      celebrations: categories.celebrations !== false,
      ads: categories.ads === true,
    };
    updates.channelName = channelLogin;
    updates.updatedAt = new Date();
    await db.collection(AUTO_CHAT_COLLECTION).doc(channelLogin).set(updates, { merge: true });
    try {
      if (typeof updates.categories?.ads === "boolean") {
        await ensureAdBreakSubscription(channelLogin, updates.categories.ads);
      }
    } catch (subErr) {
      console.warn(`[API /auto-chat POST] ensureAdBreakSubscription warning for ${channelLogin}:`, subErr.message);
    }
    return res.json({ success: true, config: updates });
  } catch (err) {
    console.error("[API /auto-chat POST] Error:", err);
    return res.status(500).json({ success: false, message: "Failed to save auto-chat config." });
  }
});

// Cache for app access token (these last 60 days but we'll refresh every 50 days)
let appAccessTokenCache = null;
let appAccessTokenExpiry = 0;

async function getAppAccessToken() {
  // Return cached token if still valid (with 1 hour buffer)
  if (appAccessTokenCache && Date.now() < appAccessTokenExpiry - 3600000) {
    return appAccessTokenCache;
  }

  // Get new app access token using client credentials flow
  try {
    const response = await axios.post("https://id.twitch.tv/oauth2/token", null, {
      params: {
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
        grant_type: "client_credentials",
      },
    });

    appAccessTokenCache = response.data.access_token;
    const expiresIn = response.data.expires_in || 5184000; // Default 60 days
    appAccessTokenExpiry = Date.now() + (expiresIn * 1000);

    console.log(`[getAppAccessToken] Obtained new app access token (expires in ${Math.floor(expiresIn / 86400)} days)`);
    return appAccessTokenCache;
  } catch (error) {
    console.error("[getAppAccessToken] Failed to get app access token:", error.message);
    throw error;
  }
}

async function ensureAdBreakSubscription(channelLogin, adsEnabled) {
  if (!BOT_PUBLIC_URL) {
    return;
  }
  try {
    // Get user ID from Firestore
    const userDocRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
    const userDoc = await userDocRef.get();
    const userId = userDoc.exists ? userDoc.data().twitchUserId : null;
    if (!userId) return;

    // Verify user has granted channel:read:ads scope by validating their token
    // (This doesn't create the subscription, just confirms they have permission)
    try {
      const userToken = await getValidTwitchTokenForUser(channelLogin);
      const validateResponse = await axios.get("https://id.twitch.tv/oauth2/validate", {
        headers: { Authorization: `OAuth ${userToken}` },
      });
      const scopes = validateResponse.data.scopes || [];
      console.log(`[ensureAdBreakSubscription] User token validation for ${channelLogin}:`, {
        userId: validateResponse.data.user_id,
        scopes,
        hasAdsScope: scopes.includes("channel:read:ads"),
      });
      if (!scopes.includes("channel:read:ads")) {
        console.error(`[ensureAdBreakSubscription] User ${channelLogin} hasn't granted channel:read:ads scope`);
        return; // Skip subscription if user hasn't granted scope
      }
    } catch (validateErr) {
      console.error(`[ensureAdBreakSubscription] User token validation failed for ${channelLogin}:`, validateErr.message);
      return;
    }

    // Use APP access token for EventSub webhook subscription (required by Twitch)
    const appAccessToken = await getAppAccessToken();
    console.log(`[ensureAdBreakSubscription] Using app access token for ${channelLogin}:`, {
      tokenPrefix: appAccessToken ? appAccessToken.substring(0, 8) + "..." : "null",
      tokenType: typeof appAccessToken,
    });
    const HELIX_URL = "https://api.twitch.tv/helix";
    const headers = {
      Authorization: `Bearer ${appAccessToken}`,
      "Client-ID": TWITCH_CLIENT_ID,
      "Content-Type": "application/json",
    };
    const list = await axios.get(`${HELIX_URL}/eventsub/subscriptions`, { headers });
    const existing = (list.data && list.data.data ? list.data.data : []).filter(
      (s) => s.type === "channel.ad_break.begin" && s.condition?.broadcaster_user_id === String(userId),
    );
    if (adsEnabled) {
      if (existing.length > 0) return;
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
      console.log(`[ensureAdBreakSubscription] Creating subscription for ${channelLogin}:`, {
        userId,
        authHeaderPrefix: headers.Authorization?.substring(0, 15) + "...",
        clientId: headers["Client-ID"],
      });
      await axios.post(`${HELIX_URL}/eventsub/subscriptions`, body, { headers });
      return;
    } else {
      for (const sub of existing) {
        await axios.delete(`${HELIX_URL}/eventsub/subscriptions`, {
          headers,
          params: { id: sub.id },
        });
      }
      return;
    }
  } catch (e) {
    // Enhanced error logging for debugging EventSub subscription issues
    console.error(`[ensureAdBreakSubscription] Error for ${channelLogin}:`, {
      message: e.message,
      status: e.response?.status,
      statusText: e.response?.statusText,
      twitchError: e.response?.data,
      adsEnabled,
    });
    throw e;
  }
}

// Internal bot-only route (uses INTERNAL_BOT_TOKEN). Requires ?channel=
app.get("/internal/ads/schedule", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    const expected = await getInternalBotTokenValue();
    if (!token || token !== expected) {
      console.error("[AdSchedule] Unauthorized request - invalid internal token");
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    
    const channelLogin = (req.query.channel || "").toString().toLowerCase();
    if (!channelLogin) {
      console.error("[AdSchedule] Missing channel parameter in request");
      return res.status(400).json({ success: false, message: "Missing channel parameter" });
    }
    if (!db) {
      console.error("[AdSchedule] Firestore not initialized");
      return res.status(500).json({ success: false, message: "Firestore not available." });
    }
    
    console.log(`[AdSchedule] Fetching ad schedule for channel: ${channelLogin}`);
    
    // Get valid access token (refreshes if needed)
    const accessToken = await getValidTwitchTokenForUser(channelLogin);
    
    // Get user ID
    const userDoc = await db.collection(CHANNELS_COLLECTION).doc(channelLogin).get();
    const userId = userDoc.exists ? userDoc.data().twitchUserId : null;
    if (!userId) {
      console.error(`[AdSchedule] No twitchUserId found for ${channelLogin}`);
      return res.status(404).json({ success: false, message: "User not found or missing Twitch user ID" });
    }
    
    console.log(`[AdSchedule] Calling Twitch API for broadcaster_id: ${userId}`);
    
    // Call Twitch API
    const response = await axios.get("https://api.twitch.tv/helix/channels/ads", {
      headers: { Authorization: `Bearer ${accessToken}`, "Client-ID": TWITCH_CLIENT_ID },
      params: { broadcaster_id: String(userId) },
      timeout: 15000,
    });
    
    // Log the Twitch API response for debugging
    console.log(`[AdSchedule] Twitch API response for ${channelLogin}:`, JSON.stringify(response.data, null, 2));
    
    return res.json({ success: true, data: response.data });
  } catch (e) {
    // Enhanced error logging - extract channel from query if available
    const channelLogin = (req.query?.channel || "unknown").toString().toLowerCase();
    const errorDetails = {
      channel: channelLogin,
      message: e.message,
      twitchApiError: e.response?.data,
      status: e.response?.status,
      stack: e.stack,
    };
    console.error("[AdSchedule] Error fetching ad schedule:", JSON.stringify(errorDetails, null, 2));
    
    // Return appropriate status code
    const statusCode = e.response?.status || 500;
    return res.status(statusCode).json({ 
      success: false, 
      message: e.message, 
      details: e.response?.data,
    });
  }
});

app.post("/internal/eventsub/adbreak/ensure", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    const expected = await getInternalBotTokenValue();
    if (!token || token !== expected) {
      console.error("[EventSub /adbreak/ensure] Unauthorized");
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    const { channelLogin, adsEnabled } = req.body;
    if (!channelLogin) {
      return res.status(400).json({ success: false, message: "Missing channelLogin" });
    }
    await ensureAdBreakSubscription(channelLogin, adsEnabled === true);
    return res.json({ success: true, message: `EventSub ad-break subscription updated for ${channelLogin}` });
  } catch (e) {
    console.error("[EventSub /adbreak/ensure] Error:", e.message);
    return res.status(500).json({ success: false, message: e.message });
  }
});

app.post("/internal/commands/save", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
    const expected = await getInternalBotTokenValue();
    if (!token || token !== expected) {
      console.error("[Internal /commands/save] Unauthorized");
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    const { channelLogin, commandSettings } = req.body;
    if (!channelLogin || typeof commandSettings !== "object") {
      return res.status(400).json({ success: false, message: "Invalid request body" });
    }
    if (!db) {
      return res.status(500).json({ success: false, message: "Firestore not available." });
    }
    const docRef = db.collection("channelCommands").doc(channelLogin);
    const updates = {};
    for (const cmd of Object.keys(commandSettings)) {
      updates[cmd] = commandSettings[cmd];
    }
    updates.lastUpdatedAt = FieldValue.serverTimestamp();
    await docRef.set(updates, { merge: true });
    console.log(`[Internal /commands/save] Saved command settings for ${channelLogin}`);
    return res.json({ success: true, message: "Command settings saved successfully." });
  } catch (error) {
    console.error("[Internal /commands/save] Error:", error);
    return res.status(500).json({ success: false, message: "Error saving command settings." });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("session_token", { path: "/" });
  res.redirect(FRONTEND_URL_CONFIG);
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("session_token", { path: "/" });
  res.json({ success: true, message: "Logged out successfully." });
});

app.get("/api/auth/status", apiLimiter, authenticateApiRequest, async (req, res) => {
  const userLogin = req.user.login;
  console.log(`[API /auth/status] Checking auth status for ${userLogin}`);
  if (!db) {
    console.error("[API /auth/status] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    await getValidTwitchTokenForUser(userLogin);
    return res.json({
      success: true,
      isAuthenticated: true,
      needsReAuth: false,
      message: "Twitch authentication is valid.",
    });
  } catch (error) {
    console.error(`[API /auth/status] Error getting valid token for ${userLogin}:`, error.message);
    const needsReAuth = error.message.includes("re-authenticate") ||
      error.message.includes("Refresh token not available") ||
      error.message.includes("User not found");
    return res.status(403).json({
      success: false,
      isAuthenticated: true,
      needsReAuth: needsReAuth,
      message: needsReAuth ?
        "Twitch authentication required. Please re-authenticate with Twitch." :
        "Error validating Twitch authentication.",
    });
  }
});

app.post("/api/auth/refresh", apiLimiter, authenticateApiRequest, async (req, res) => {
  const userLogin = req.user.login;
  console.log(`[API /auth/refresh] Forcing token refresh for ${userLogin}`);
  if (!db) {
    console.error("[API /auth/refresh] Firestore (db) not initialized!");
    return res.status(500).json({ success: false, message: "Firestore not available." });
  }
  try {
    await clearCachedTokens(userLogin, "Manual refresh requested by user");
    const accessToken = await getValidTwitchTokenForUser(userLogin);
    if (!accessToken) {
      throw new Error("Failed to obtain access token after refresh.");
    }
    console.log(`[API /auth/refresh] Successfully refreshed token for ${userLogin}`);
    return res.json({
      success: true,
      message: "Twitch authentication successfully refreshed.",
    });
  } catch (error) {
    console.error(`[API /auth/refresh] Error refreshing token for ${userLogin}:`, error.message);
    const needsReAuth = error.message.includes("re-authenticate") ||
      error.message.includes("Refresh token not available") ||
      error.message.includes("User not found");
    return res.status(403).json({
      success: false,
      needsReAuth: needsReAuth,
      message: needsReAuth ?
        "Twitch re-authentication required. Please log in with Twitch again." :
        "Error refreshing Twitch authentication.",
    });
  }
});

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
      lastTokenClearReason: reason,
      lastTokenClearAt: FieldValue.serverTimestamp(),
    });
    console.log(`[clearCachedTokens] Cleared cached tokens for ${userLogin}. Reason: ${reason}`);
    return true;
  } catch (error) {
    console.error(`[clearCachedTokens] Failed to clear tokens for ${userLogin}:`, error.message);
    return false;
  }
}

async function refreshTwitchToken(currentRefreshToken) {
  if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET) {
    console.error("Twitch client ID or secret not configured for token refresh.");
    throw new Error("Server configuration error for Twitch token refresh.");
  }
  const MAX_RETRY_ATTEMPTS = 3;
  const RETRY_DELAY_MS = 5000;
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
        timeout: 15000,
      });
      if (response.status === 200 && response.data && response.data.access_token) {
        console.log(`Successfully refreshed Twitch token on attempt ${attempt}.`);
        
        // Validate the refreshed token
        try {
          await axios.get(TWITCH_VALIDATE_URL, {
            headers: { Authorization: `Bearer ${response.data.access_token}` },
            timeout: 15000,
          });
          console.log(`Refreshed token validated successfully on attempt ${attempt}.`);
        } catch (validateError) {
          console.error(`Failed to validate refreshed token on attempt ${attempt}:`, validateError.message);
          throw new Error("Refreshed token validation failed");
        }
        
        return {
          accessToken: response.data.access_token,
          refreshToken: response.data.refresh_token || currentRefreshToken,
          expiresIn: response.data.expires_in,
        };
      } else {
        lastError = new Error(`Failed to fetch token, unexpected response structure. Status: ${response.status}`);
        console.warn(`Attempt ${attempt} failed: ${lastError.message}`);
      }
    } catch (error) {
      lastError = error;
      const statusCode = error.response?.status;
      const errorData = error.response?.data;
      console.error(`Attempt ${attempt} failed with error:`, error.message, errorData);
      if (statusCode === 400 || statusCode === 401) {
        console.error("Token refresh failed due to invalid refresh token. User needs to re-authenticate.");
        throw new Error("Refresh token is invalid or expired. User needs to re-authenticate.");
      }
      if (attempt < MAX_RETRY_ATTEMPTS) {
        console.log(`Retrying in ${RETRY_DELAY_MS / 1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS));
      }
    }
  }
  const finalErrorMessage = lastError?.response?.data?.message ||
    lastError?.message ||
    "Failed to refresh Twitch token after multiple attempts.";
  console.error("All refresh attempts failed. Final error:", finalErrorMessage);
  throw new Error(finalErrorMessage);
}

async function getValidTwitchTokenForUser(userLogin) {
  if (!db) {
    console.error("[getValidTwitchTokenForUser] Firestore (db) not initialized!");
    throw new Error("Firestore not available.");
  }
  
  // Check cache first - if token exists and not expired, use it
  const cached = tokenCache.get(userLogin);
  if (cached && cached.expiresAt > Date.now()) {
    console.log(`[getValidTwitchTokenForUser] Using cached token for ${userLogin} (expires in ${Math.floor((cached.expiresAt - Date.now()) / 1000)}s)`);
    return cached.token;
  }
  
  const userDocRef = db.collection(CHANNELS_COLLECTION).doc(userLogin);
  const userDoc = await userDocRef.get();
  if (!userDoc.exists) {
    console.warn(`[getValidTwitchTokenForUser] User document for ${userLogin} not found.`);
    throw new Error("User not found or not authenticated with Twitch.");
  }
  const userData = userDoc.data();
  const { refreshTokenSecretPath } = userData;
  if (!refreshTokenSecretPath) {
    console.warn(`[getValidTwitchTokenForUser] No refresh token secret path found for ${userLogin}. Re-authentication required.`);
    throw new Error("Refresh token not available. User needs to re-authenticate.");
  }
  console.log(`[getValidTwitchTokenForUser] Refreshing access token for ${userLogin} from refresh token.`);
  try {
    const [version] = await secretManagerClient.accessSecretVersion({ name: refreshTokenSecretPath });
    const currentRefreshToken = version.payload.data.toString("utf8");

    console.log(`[getValidTwitchTokenForUser] Current refresh token for ${userLogin}: ${currentRefreshToken.substring(0, 8)}...${currentRefreshToken.substring(currentRefreshToken.length - 8)}`);

    const newTokens = await refreshTwitchToken(currentRefreshToken);

    // CRITICAL: Twitch rotates refresh tokens on every use
    // We MUST save the new refresh token back to Secret Manager
    if (newTokens.refreshToken && newTokens.refreshToken !== currentRefreshToken) {
      console.log(`[getValidTwitchTokenForUser] 🔄 Refresh token rotated by Twitch for ${userLogin}`);
      console.log(`[getValidTwitchTokenForUser] Old token: ${currentRefreshToken.substring(0, 8)}...${currentRefreshToken.substring(currentRefreshToken.length - 8)}`);
      console.log(`[getValidTwitchTokenForUser] New token: ${newTokens.refreshToken.substring(0, 8)}...${newTokens.refreshToken.substring(newTokens.refreshToken.length - 8)}`);

      try {
        // Extract the secret name (without version) from the path
        const secretName = refreshTokenSecretPath.split("/versions/")[0];

        // Add new version to Secret Manager
        const [newVersion] = await secretManagerClient.addSecretVersion({
          parent: secretName,
          payload: {
            data: Buffer.from(newTokens.refreshToken, "utf8"),
          },
        });

        console.log(`[getValidTwitchTokenForUser] ✅ New refresh token saved to Secret Manager for ${userLogin}: ${newVersion.name}`);

        // Update Firestore to point to the new version
        await userDocRef.update({
          refreshTokenSecretPath: newVersion.name,
          lastTokenRefreshAt: FieldValue.serverTimestamp(),
          needsTwitchReAuth: false,
        });
        console.log(`[getValidTwitchTokenForUser] ✅ Updated Firestore with new secret version path for ${userLogin}`);

      } catch (secretError) {
        console.error(`[getValidTwitchTokenForUser] ❌ CRITICAL: Failed to save new refresh token for ${userLogin}:`, secretError.message);
        console.error("[getValidTwitchTokenForUser] This will cause authentication to fail on next token refresh!");
        // Don't throw - we still have a valid access token for this request
      }
    } else if (!newTokens.refreshToken) {
      console.warn(`[getValidTwitchTokenForUser] ⚠️  Twitch did not return a new refresh token for ${userLogin} (unexpected)`);
      await userDocRef.update({
        lastTokenRefreshAt: FieldValue.serverTimestamp(),
        needsTwitchReAuth: false,
      });
    } else {
      console.log(`[getValidTwitchTokenForUser] Refresh token unchanged for ${userLogin} (reusing same token)`);
      await userDocRef.update({
        lastTokenRefreshAt: FieldValue.serverTimestamp(),
        needsTwitchReAuth: false,
      });
    }

    // Cache the new access token (with 5 minute buffer before actual expiry)
    const expiresAt = Date.now() + ((newTokens.expiresIn - 300) * 1000);
    tokenCache.set(userLogin, {
      token: newTokens.accessToken,
      expiresAt,
    });
    console.log(`[getValidTwitchTokenForUser] Cached new access token for ${userLogin} (expires in ${newTokens.expiresIn}s)`);
    console.log(`[getValidTwitchTokenForUser] Successfully refreshed access token for ${userLogin}.`);
    return newTokens.accessToken;
  } catch (error) {
    console.error(`[getValidTwitchTokenForUser] Failed to refresh token for ${userLogin}:`, error.message);
    // Clear cache on error
    tokenCache.delete(userLogin);
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

/**
 * Gets a Twitch user ID from a username (login)
 * @param {string} username - The Twitch username
 * @return {Promise<string|null>} The user ID or null if not found
 */
async function getUserIdFromUsername(username) {
  try {
    const appAccessToken = await getAppAccessToken();
    const response = await axios.get("https://api.twitch.tv/helix/users", {
      params: { login: username.toLowerCase() },
      headers: {
        "Client-Id": TWITCH_CLIENT_ID,
        "Authorization": `Bearer ${appAccessToken}`,
      },
      timeout: 15000,
    });

    if (response.data?.data && response.data.data.length > 0) {
      return response.data.data[0].id;
    }
    return null;
  } catch (error) {
    console.error(`[getUserIdFromUsername] Error getting user ID for ${username}:`, error.response?.data || error.message);
    return null;
  }
}

/**
 * Adds a user as a moderator in a broadcaster's channel
 * @param {string} broadcasterLogin - The broadcaster's Twitch login
 * @param {string} broadcasterId - The broadcaster's Twitch user ID
 * @param {string} moderatorUserId - The user ID to add as moderator
 * @return {Promise<{success: boolean, error?: string}>} Success status and optional error message
 */
async function addModerator(broadcasterLogin, broadcasterId, moderatorUserId) {
  try {
    const accessToken = await getValidTwitchTokenForUser(broadcasterLogin);

    const response = await axios.post(
      "https://api.twitch.tv/helix/moderation/moderators",
      {},
      {
        params: {
          broadcaster_id: broadcasterId,
          user_id: moderatorUserId,
        },
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Client-Id": TWITCH_CLIENT_ID,
        },
        timeout: 15000,
      },
    );

    // 204 No Content means success (moderator was added)
    if (response.status === 204) {
      console.log(`[addModerator] Successfully added moderator ${moderatorUserId} to channel ${broadcasterLogin}`);
      return { success: true };
    }

    return { success: false, error: `Unexpected status: ${response.status}` };
  } catch (error) {
    const status = error.response?.status;
    const errorData = error.response?.data;
    const errorMessage = errorData?.message || error.message;

    // 400 Bad Request - could be: already moderator, banned, or VIP
    if (status === 400) {
      if (errorMessage?.toLowerCase().includes("already") || errorMessage?.toLowerCase().includes("moderator")) {
        console.log(`[addModerator] User ${moderatorUserId} is already a moderator in ${broadcasterLogin}`);
        return { success: true }; // Already a mod, treat as success
      }
      // User might be banned or VIP - log for debugging
      console.warn(`[addModerator] Cannot add ${moderatorUserId} as moderator in ${broadcasterLogin}: ${errorMessage}`);
      return { success: false, error: errorMessage || "User cannot be added as moderator (may be banned or VIP)" };
    }

    // 403 Forbidden - broadcaster doesn't have channel:manage:moderators scope
    if (status === 403) {
      console.warn(`[addModerator] Broadcaster ${broadcasterLogin} lacks channel:manage:moderators scope`);
      return { success: false, error: "Missing channel:manage:moderators scope. Please re-authenticate." };
    }

    // 401 Unauthorized - token invalid or expired
    if (status === 401) {
      console.warn(`[addModerator] Authentication failed for ${broadcasterLogin}`);
      return { success: false, error: "Authentication failed. Please re-authenticate." };
    }

    // 404 Not Found - user or broadcaster doesn't exist
    if (status === 404) {
      console.warn("[addModerator] User or broadcaster not found");
      return { success: false, error: "User or broadcaster not found" };
    }

    // Other errors
    console.error(`[addModerator] Error adding moderator ${moderatorUserId} to ${broadcasterLogin}:`, errorData || errorMessage);
    return { success: false, error: errorMessage || "Unknown error occurred" };
  }
}

exports.webUi = functions.https.onRequest(app);

