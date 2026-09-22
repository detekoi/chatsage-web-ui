/**
 * Firestore document keys for channel-scoped data.
 *
 * Every per-channel collection the dashboard writes (timers, custom commands,
 * command settings, auto-chat, language, check-in, personas) is keyed by the
 * broadcaster's Twitch user ID, never by login. Logins are mutable: a user can
 * rename, and Twitch eventually releases the old name for someone else to
 * register, so a login-keyed document orphans on rename and can be inherited
 * by the next owner of the name. The bot reads the same documents through
 * twitch-knowledge-bot/src/lib/channelKey.js; keep the two in step.
 *
 * The login is still stored on the parent document as `channelName`, for
 * readability in the console only. Nothing should look a channel up by it.
 */

export interface ChannelIdentity {
  userId: string;
  login: string;
}

/**
 * The document key for the authenticated broadcaster's channel data.
 * @throws when the session carries no usable Twitch user ID, which should be
 *   impossible past the JWT middleware and is therefore a bug, not a 4xx.
 */
export function channelDocKey(user: ChannelIdentity): string {
  const id = user?.userId ? String(user.userId).trim() : "";
  if (!/^\d+$/.test(id)) {
    throw new Error(`No broadcaster ID for channel "${user?.login ?? "?"}"`);
  }
  return id;
}
