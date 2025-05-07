const functions = require("firebase-functions");
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const cookieParser = require("cookie-parser"); // For session/token management
const admin = require("firebase-admin"); // If using firebase-admin SDK for Firestore
const jwt = require('jsonwebtoken'); // <-- Import jsonwebtoken

// --- Initialize Firebase Admin (if not already done in your project for other functions) ---
// admin.initializeApp(); // Call this only ONCE per project, typically at the top level.
// const db = admin.firestore();
// OR, if using @google-cloud/firestore directly with service account (less common for functions but possible)
const { Firestore, FieldValue } = require('@google-cloud/firestore');
let db;
try {
    // Ensure your Cloud Functions environment has access to Firestore.
    // This typically works out-of-the-box if functions are in the same GCP project.
    // Or, set GOOGLE_APPLICATION_CREDENTIALS for local emulation.
    db = new Firestore();
    console.log('[CloudFunctions] Firestore client initialized.');
} catch (e) {
    console.error("[CloudFunctions] Firestore client init error:", e);
}

const CHANNELS_COLLECTION = 'managedChannels'; // Must match your bot's collection name

const app = express();
app.use(cookieParser(functions.config().web ? functions.config().web.session_secret : process.env.WEB_UI_SESSION_SECRET)); // Pass secret to cookieParser for signed cookies, though not strictly necessary for this simple state cookie

// --- Environment Configuration for Functions ---
// Set these in Firebase: `firebase functions:config:set twitch.client_id="YOUR_ID" twitch.client_secret="YOUR_SECRET" web.redirect_uri="YOUR_FUNCTION_CALLBACK_URL" web.session_secret="VERY_SECRET"`
// Access them via functions.config().twitch.client_id, etc.
const TWITCH_CLIENT_ID = functions.config().twitch ? functions.config().twitch.client_id : process.env.TWITCH_CLIENT_ID_FOR_FUNCTIONS;
const TWITCH_CLIENT_SECRET = functions.config().twitch ? functions.config().twitch.client_secret : process.env.TWITCH_CLIENT_SECRET_FOR_FUNCTIONS;
const CALLBACK_REDIRECT_URI_CONFIG = functions.config().web ? functions.config().web.redirect_uri : process.env.WEB_UI_TWITCH_REDIRECT_URI_ALTERNATIVE;
const FRONTEND_URL_CONFIG = functions.config().frontend ? functions.config().frontend.url : "http://127.0.0.1:5002"; // Default to local hosting emulator

const TWITCH_AUTH_URL = 'https://id.twitch.tv/oauth2/authorize';
const TWITCH_TOKEN_URL = 'https://id.twitch.tv/oauth2/token';
const TWITCH_VALIDATE_URL = 'https://id.twitch.tv/oauth2/validate';

// --- JWT Config ---
const JWT_SECRET = functions.config().auth ? functions.config().auth.jwt_secret : process.env.AUTH_JWT_SECRET; // Fallback for local env if needed
const JWT_EXPIRATION = '1h'; // Example: tokens expire in 1 hour

// CORS Middleware (IMPORTANT if frontend is on different domain like GitHub Pages)
app.use((req, res, next) => {
    const allowedOrigins = [
        (functions.config().frontend ? functions.config().frontend.url : null), // For deployed
        "http://127.0.0.1:5002", // Your local hosting emulator
        "http://localhost:5002"
    ].filter(Boolean);

    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true'); // Necessary for cookies in cross-origin requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// Route: /auth/twitch/initiate (NEW NAME)
// This function now returns data to the frontend, instead of redirecting directly.
app.get("/auth/twitch/initiate", (req, res) => {
    console.log("--- /auth/twitch/initiate HIT ---");
    const conf = functions.config();
    const currentTwitchClientId = TWITCH_CLIENT_ID;
    const currentCallbackRedirectUri = CALLBACK_REDIRECT_URI_CONFIG; // ngrok HTTPS URL

    if (!currentTwitchClientId || !currentCallbackRedirectUri) {
        console.error("Config missing for /auth/twitch/initiate");
        return res.status(500).json({ success: false, error: "Server configuration error for Twitch auth." });
    }

    const state = crypto.randomBytes(16).toString("hex");
    const params = new URLSearchParams({
        client_id: currentTwitchClientId,
        redirect_uri: currentCallbackRedirectUri,
        response_type: "code",
        scope: "user:read:email",
        state: state, // Function generates state
        force_verify: "true",
    });
    const twitchAuthUrl = `${TWITCH_AUTH_URL}?${params.toString()}`;

    console.log(`Generated state: ${state}`);
    console.log(`Twitch Auth URL to be sent to frontend: ${twitchAuthUrl}`);

    // Send the URL and state back to the frontend
    res.json({
        success: true,
        twitchAuthUrl: twitchAuthUrl,
        state: state // Send state for frontend to store
    });
});

// Route: /auth/twitch/callback (MODIFIED to issue JWT)
app.get("/auth/twitch/callback", async (req, res) => {
    console.log("--- /auth/twitch/callback HIT ---");
    console.log("Callback Request Query Params:", JSON.stringify(req.query));
    const { code, state: twitchQueryState } = req.query;

    if (!twitchQueryState) {
        console.error("State parameter missing from Twitch callback.");
        return res.status(400).send("State parameter missing from Twitch callback. Please try logging in again.");
    }
    if (!code) {
        console.error("Authorization code not provided by Twitch in callback.");
        return res.status(400).send("Authorization code not provided by Twitch. Please try logging in again.");
    }

    try {
        console.log("Exchanging code for token. Callback redirect_uri used for exchange:", CALLBACK_REDIRECT_URI_CONFIG);
        const tokenResponse = await axios.post(TWITCH_TOKEN_URL, null, {
            params: {
                client_id: TWITCH_CLIENT_ID,
                client_secret: TWITCH_CLIENT_SECRET,
                code: code,
                grant_type: "authorization_code",
                redirect_uri: CALLBACK_REDIRECT_URI_CONFIG,
            },
        });
        const accessToken = tokenResponse.data.access_token;
        console.log("Access token received from Twitch.");

        const validateResponse = await axios.get(TWITCH_VALIDATE_URL, {
            headers: { Authorization: `OAuth ${accessToken}` },
        });

        if (validateResponse.data && validateResponse.data.user_id) {
            const twitchUser = {
                id: validateResponse.data.user_id,
                login: validateResponse.data.login.toLowerCase(),
                displayName: validateResponse.data.login,
            };
            console.log(`[AuthCallback] User ${twitchUser.login} authenticated and validated.`);

            if (!JWT_SECRET) {
                console.error("JWT_SECRET is not configured in Firebase Functions environment.");
                return res.status(500).send("Server configuration error (JWT signing).");
            }

            // Generate your own JWT
            const appTokenPayload = {
                userId: twitchUser.id,
                userLogin: twitchUser.login,
                displayName: twitchUser.displayName
            };
            const appSessionToken = jwt.sign(appTokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRATION });
            console.log(`Generated app session token for ${twitchUser.login}`);

            const frontendAuthCompleteUrl = new URL(FRONTEND_URL_CONFIG);
            frontendAuthCompleteUrl.pathname = '/auth-complete.html';
            frontendAuthCompleteUrl.searchParams.append('user_login', twitchUser.login);
            frontendAuthCompleteUrl.searchParams.append('user_id', twitchUser.id);
            frontendAuthCompleteUrl.searchParams.append('state', twitchQueryState);
            frontendAuthCompleteUrl.searchParams.append('session_token', appSessionToken); // <-- Send JWT to frontend

            console.log(`Redirecting to frontend auth-complete page: ${frontendAuthCompleteUrl.toString()}`);
            return res.redirect(frontendAuthCompleteUrl.toString());
        } else {
            console.error("Failed to validate token or get user info from Twitch after token exchange.");
            throw new Error("Failed to validate token or get user info from Twitch.");
        }
    } catch (error) {
        console.error("[AuthCallback] Twitch OAuth callback error:", error.response ? error.response.data : error.message, error.stack);
        return res.status(500).send("Authentication failed with Twitch.");
    }
});

// --- JWT Authentication Middleware for API routes ---
const authenticateApiRequest = (req, res, next) => {
    console.log(`--- authenticateApiRequest for ${req.path} ---`);
    const authHeader = req.headers.authorization;
    console.log("Received Authorization Header:", authHeader);

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn("API Auth Middleware: Missing or malformed Authorization header.");
        return res.status(401).json({ success: false, message: "Unauthorized: Missing or malformed token." });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        console.warn("API Auth Middleware: Token not found after Bearer prefix.");
        return res.status(401).json({ success: false, message: "Unauthorized: Token not found." });
    }
    console.log("API Auth Middleware: Token extracted:", token ? "Present" : "MISSING_OR_EMPTY");

    if (!JWT_SECRET) {
        console.error("API Auth: JWT_SECRET is not configured. Cannot verify token.");
        return res.status(500).json({ success: false, message: "Server error: Auth misconfiguration." });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = {
            id: decoded.userId,
            login: decoded.userLogin,
            displayName: decoded.displayName
        };
        console.log(`API Auth Middleware: User ${req.user.login} successfully authenticated via JWT. Decoded:`, JSON.stringify(decoded));
        next();
    } catch (err) {
        console.warn("API Auth Middleware: JWT verification failed.", err.message, err.name);
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: "Unauthorized: Token expired." });
        }
        return res.status(401).json({ success: false, message: "Unauthorized: Invalid token." });
    }
};

// --- API Routes now require JWT authentication ---
app.get("/api/bot/status", authenticateApiRequest, async (req, res) => {
    const channelLogin = req.user.login;
    if (!db) return res.status(500).json({ success: false, message: 'Firestore not available.' });
    try {
        const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
        const docSnap = await docRef.get();
        if (docSnap.exists && docSnap.data().isActive) {
            res.json({ success: true, isActive: true, channelName: docSnap.data().channelName || channelLogin });
        } else {
            res.json({ success: true, isActive: false, channelName: channelLogin });
        }
    } catch (error) {
        console.error(`[API /status] Error getting status for ${channelLogin}:`, error);
        res.status(500).json({ success: false, message: "Error fetching bot status." });
    }
});

app.post("/api/bot/add", authenticateApiRequest, async (req, res) => {
    const { id: twitchUserId, login: channelLogin, displayName } = req.user;
    if (!db) return res.status(500).json({ success: false, message: 'Firestore not available.' });
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
        }, { merge: true });
        console.log(`[API /add] Bot activated for channel: ${channelLogin}`);
        res.json({ success: true, message: `Bot has been requested for ${channelLogin}. It should join shortly!` });
    } catch (error) {
        console.error(`[API /add] Error activating bot for ${channelLogin}:`, error);
        res.status(500).json({ success: false, message: "Error requesting bot." });
    }
});

app.post("/api/bot/remove", authenticateApiRequest, async (req, res) => {
    const channelLogin = req.user.login;
    if (!db) return res.status(500).json({ success: false, message: 'Firestore not available.' });
    const docRef = db.collection(CHANNELS_COLLECTION).doc(channelLogin);
    try {
        const docSnap = await docRef.get();
        if (docSnap.exists) {
            await docRef.update({
                isActive: false,
                lastStatusChange: FieldValue.serverTimestamp(),
            });
            console.log(`[API /remove] Bot deactivated for channel: ${channelLogin}`);
            res.json({ success: true, message: `Bot has been requested to leave ${channelLogin}.` });
        } else {
            res.json({ success: false, message: "Bot was not in your channel." });
        }
    } catch (error) {
        console.error(`[API /remove] Error deactivating bot for ${channelLogin}:`, error);
        res.status(500).json({ success: false, message: "Error requesting bot removal." });
    }
});

// Route: /auth/logout (optional, if you want to blacklist tokens, but usually client just deletes it)
app.get("/auth/logout", (req, res) => {
    // For JWTs, logout is typically handled client-side by deleting the token.
    // If you implement a token blacklist on the server, you'd add the token here.
    console.log("Logout requested. Client should clear its token.");
    res.redirect(FRONTEND_URL_CONFIG);
});

// Expose Express app as a single Cloud Function:
exports.webUi = functions.https.onRequest(app);