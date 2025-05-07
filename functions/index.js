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
const TWITCH_CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET;
const CALLBACK_REDIRECT_URI_CONFIG = process.env.CALLBACK_URL; // Renamed for clarity
const FRONTEND_URL_CONFIG = process.env.FRONTEND_URL || "http://127.0.0.1:5002"; // Fallback for local
const JWT_SECRET = process.env.JWT_SECRET_KEY; // Renamed for clarity
const JWT_EXPIRATION = "1h";
const SESSION_SECRET_FOR_COOKIE_PARSER = process.env.SESSION_COOKIE_SECRET || "default-fallback-session-secret-string";

app.use(cookieParser(SESSION_SECRET_FOR_COOKIE_PARSER));

// CORS Middleware
app.use((req, res, next) => {
  const allowedOrigins = [
    FRONTEND_URL_CONFIG, // This will be the live URL when deployed, or local from .env
    "http://127.0.0.1:5002", // Explicitly for local dev
    "http://localhost:5002", // Explicitly for local dev
  ].filter(Boolean);

  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  // Allow ngrok origins dynamically for local testing if you use it
  if (origin && origin.includes("ngrok-free.app")) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
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
  const {code, state: twitchQueryState} = req.query;

  if (!twitchQueryState) {
    console.error("State parameter missing from Twitch callback.");
    return res.status(400).send("State parameter missing from Twitch callback. Please try logging in again.");
  }
  if (!code) {
    console.error("Authorization code not provided by Twitch in callback.");
    return res.status(400).send("Authorization code not provided by Twitch. Please try logging in again.");
  }

  try {
    console.log("Exchanging code for token. Callback redirect_uri used for exchange:", CALLBACK_REDIRECT_URI_CONFIG); // This is from .env
    const tokenResponse = await axios.post(TWITCH_TOKEN_URL, null, {
      params: {
        client_id: TWITCH_CLIENT_ID, // from .env
        client_secret: TWITCH_CLIENT_SECRET, // from .env
        code: code,
        grant_type: "authorization_code",
        redirect_uri: CALLBACK_REDIRECT_URI_CONFIG, // from .env
      },
    });
    const accessToken = tokenResponse.data.access_token;
    console.log("Access token received from Twitch.");

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
      return res.redirect(frontendAuthCompleteUrl.toString());
    } else {
      console.error("Failed to validate token or get user info from Twitch after token exchange.");
      throw new Error("Failed to validate token or get user info from Twitch.");
    }
  } catch (error) {
    console.error("[AuthCallback] Twitch OAuth callback error:", error.response ? JSON.stringify(error.response.data, null, 2) : error.message, error.stack);
    return res.status(500).send("Authentication failed with Twitch.");
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
  // ... rest of the logic ...
  try {
    const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
    const docSnap = await docRef.get();
    if (docSnap.exists && docSnap.data().isActive) {
      res.json({success: true, isActive: true, channelName: docSnap.data().channelName || channelLogin});
    } else {
      res.json({success: true, isActive: false, channelName: channelLogin});
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
  // ... rest of the logic ...
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
  // ... rest of the logic ...
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

exports.webUi = functions.https.onRequest(app);
