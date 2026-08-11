# WildcatSage Bot Management

## Description

WildcatSage Bot Management is a web application for Twitch streamers. Approved streamers can use the application to manage the WildcatSage bot on their Twitch channel, configure built-in commands, create custom commands, manage scheduled timers, configure auto-chat, and set up daily check-in rewards.

> **IMPORTANT:** Access to WildcatSage is invite-only. The interface shows an access denied message for unapproved channels. If you want to request access, use [this contact form](https://parfaitfair.com/#contact).

## Features

- **Twitch Authentication:** Log in with a Twitch account.
- **Bot Management:** Add or remove the WildcatSage bot on an approved channel and view online status.
- **Built-in Command Control:** Enable or disable individual built-in commands and set required user permissions.
- **Stream Event Messages:** Enable automated AI greetings for stream status changes, new followers, subscribers, and incoming raids.
- **Auto-Chat Settings:** Configure automatic chat messages with mode levels (off, low, medium, high) and categories (facts, questions).
- **Ad Break Notifications:** Enable automated chat alerts when ad breaks run on your channel.
- **Custom Commands:** Create and edit custom commands with static responses or AI Mode, custom permissions, cooldowns, and template variables.
- **Timed Messages:** Schedule recurring chat messages with minimum line counts, custom intervals, and static text or AI Mode.
- **Daily Check-In:** Set up a Twitch Channel Points reward for viewer daily check-ins with streak tracking and custom responses.
- **Dynamic Background:** Display an animated background in the user interface.
- **Firebase Integration:** Host the application and run backend functions on Firebase.

## Technologies Used

- **Frontend:**
  - HTML
  - CSS
  - JavaScript
- **Backend:**
  - Node.js (version 22)
  - TypeScript
  - Express.js
  - Firebase Cloud Functions
  - Firebase Hosting
- **Authentication:**
  - Twitch API (OAuth 2.0)
  - JSON Web Tokens (JWT)
- **Database:**
  - Google Cloud Firestore
- **Development Tools:**
  - npm
  - ESLint

## Setup

### 1. Prerequisites

Make sure that you install these tools before you start:

- Node.js and npm
- Firebase CLI

### 2. Firebase Project Setup

1. Create a Firebase project.
2. Enable Firestore and Authentication.
3. Configure Firebase Hosting and Cloud Functions.

### 3. Environment Variables

- **For local development (Firebase Emulator):** Create a `.env.<YOUR_PROJECT_ID>` file (for example, `.env.streamsage-bot`) in the `functions` directory. Add your variables to this file (for example, `TWITCH_CLIENT_ID=your_local_test_id`). The Firebase Emulator loads these variables when it runs locally.
- **For deployed functions (production):** Set environment variables in the Google Cloud Console for your Cloud Function. Go to your function in Google Cloud Console, edit the function, and add variables under "Runtime environment variables". Cloud Functions does not deploy `.env` files to the production environment.

### 4. Install Dependencies

1. Change to the `functions` directory.
2. Run `npm install` to install backend dependencies.

### 5. Deploy

To deploy Firebase Hosting and Cloud Functions, run:

```bash
firebase deploy
```

## Usage

> **NOTE:** Access is restricted to approved channels. If your channel is not on the allow-list, the application shows an access denied message. Use [this contact form](https://parfaitfair.com/#contact) to request access.

1. Open the hosted application URL in your browser.
2. Select **Login with Twitch** to authenticate.
3. After authentication, the application redirects your browser to the dashboard.
4. On the dashboard, approved users can perform these actions:
   - View the current status of the WildcatSage bot for your channel.
   - Add the bot to your channel or remove the bot from your channel.
   - Enable or disable built-in commands and configure command permissions.
   - Enable automated greetings for stream live events, followers, subscribers, and raids.
   - Configure auto-chat frequency modes and topic categories.
   - Turn on chat notifications for Twitch ad breaks.
   - Add, edit, or delete custom chat commands with static text or AI Mode.
   - Add, edit, or delete timed chat messages with custom intervals and chat line thresholds.
   - Configure Channel Point daily check-in rewards and streak tracking.
   - Log out from the application.