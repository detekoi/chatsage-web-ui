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
const CALLBACK_REDIRECT_URI_CONFIG = process.env.CALLBACK_URL;
const FRONTEND_URL_CONFIG = process.env.FRONTEND_URL;
const JWT_SECRET = process.env.JWT_SECRET_KEY;
const JWT_EXPIRATION = "1h";
const SESSION_SECRET_FOR_COOKIE_PARSER = process.env.SESSION_COOKIE_SECRET;

if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET || !CALLBACK_REDIRECT_URI_CONFIG || !FRONTEND_URL_CONFIG || !JWT_SECRET || !SESSION_SECRET_FOR_COOKIE_PARSER) {
  console.error("CRITICAL: One or more environment variables are missing. Check .env files and deployment configuration.");
  // For an HTTP function, you might not want to throw here as it might prevent any response.
  // But be aware that routes relying on these will fail.
  // Consider how to handle this gracefully if a variable is missing.
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
  res.cookie('twitch_oauth_state', state, {
    signed: true,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Use true in production
    maxAge: 300000, // 5 minutes
    sameSite: 'Lax'
  });
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
  const {code, state: twitchQueryState, error: twitchError, error_description: twitchErrorDescription} = req.query;
  const originalOauthState = req.signedCookies.twitch_oauth_state;

  res.clearCookie('twitch_oauth_state'); // Clear state cookie once used or if error

  if (twitchError) {
    console.error(`Twitch OAuth explicit error: ${twitchError} - ${twitchErrorDescription}`);
    return redirectToFrontendWithError(res, twitchError, twitchErrorDescription, twitchQueryState);
  }

  if (!originalOauthState) {
    console.error("Original OAuth state cookie missing or tampered.");
    return res.status(400).send("Authentication session error. Please try logging in again.");
  }

  if (originalOauthState !== twitchQueryState) {
    console.error(`State mismatch. Original: ${originalOauthState}, Received: ${twitchQueryState}`);
    return res.status(400).send("Invalid state parameter. Potential CSRF attack. Please try logging in again.");
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
    const {access_token: accessToken, refresh_token: refreshToken, expires_in: expiresIn} = tokenResponse.data;
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
          }, { merge: true });
          console.log(`Twitch tokens stored for user ${twitchUser.login}`);
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

// --- Helper function to refresh Twitch token ---
async function refreshTwitchToken(currentRefreshToken) {
  if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET) {
    console.error("Twitch client ID or secret not configured for token refresh.");
    throw new Error("Server configuration error for Twitch token refresh.");
  }
  console.log("Attempting to refresh Twitch token.");
  try {
    const response = await axios.post(TWITCH_TOKEN_URL, null, {
      params: {
        grant_type: "refresh_token",
        refresh_token: currentRefreshToken,
        client_id: TWITCH_CLIENT_ID,
        client_secret: TWITCH_CLIENT_SECRET,
      },
    });
    console.log("Successfully refreshed Twitch token.");
    return {
      accessToken: response.data.access_token,
      refreshToken: response.data.refresh_token, // Twitch might issue a new refresh token
      expiresIn: response.data.expires_in,
    };
  } catch (error) {
    console.error(
      "[refreshTwitchToken] Error refreshing token:",
      error.response ? JSON.stringify(error.response.data, null, 2) : error.message,
      error.stack
    );
    // If the refresh token is invalid (e.g., revoked by user, or expired itself),
    // Twitch often returns a 400 or 401/403.
    if (error.response && (error.response.status === 400 || error.response.status === 401 || error.response.status === 403)) {
      console.warn("Refresh token is likely invalid or revoked.");
      // This indicates the user needs to re-authenticate.
    }
    throw new Error("Failed to refresh Twitch token.");
  }
}

// --- Helper function to get a valid Twitch access token for a user ---
// This would be used internally if your backend needs to make Twitch API calls on behalf of the user.
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
  let {twitchAccessToken, twitchRefreshToken, twitchAccessTokenExpiresAt} = userData;

  if (twitchAccessToken && twitchAccessTokenExpiresAt && twitchAccessTokenExpiresAt.toDate() > new Date(Date.now() + 5 * 60 * 1000) ) { // Check if token is valid for at least 5 more minutes
    console.log(`[getValidTwitchTokenForUser] Using existing valid access token for ${userLogin}.`);
    return twitchAccessToken;
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
    });
    console.log(`[getValidTwitchTokenForUser] Successfully refreshed and stored new tokens for ${userLogin}.`);
    return newTokens.accessToken;
  } catch (error) {
    console.error(`[getValidTwitchTokenForUser] Failed to refresh token for ${userLogin}:`, error.message);
    // If refresh fails, it might be due to revoked access.
    // Mark tokens as invalid or prompt re-authentication.
    await userDocRef.update({
      twitchAccessToken: null, // Or FieldValue.delete()
      twitchAccessTokenExpiresAt: null, // Or FieldValue.delete()
      // Consider also deleting twitchRefreshToken if it's confirmed invalid
      // to force re-auth next time.
      needsTwitchReAuth: true, 
    }).catch(console.error);
    throw new Error("Failed to obtain a valid Twitch token. User may need to re-authenticate.");
  }
}

exports.webUi = functions.https.onRequest(app);
