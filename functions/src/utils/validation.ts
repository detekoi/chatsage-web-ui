/**
 * Input validation and sanitization utilities
 * Ensures all user inputs are properly validated and sanitized
 */

import validator from "validator";

/**
 * Sanitizes and validates a Twitch username
 * @param username - The username to sanitize
 * @returns Sanitized username in lowercase
 * @throws Error if username is invalid
 */
export function sanitizeUsername(username: unknown): string {
  if (!username || typeof username !== "string") {
    throw new Error("Invalid username: must be a non-empty string");
  }

  const trimmed = username.trim().toLowerCase();

  // Twitch usernames: 4-25 characters, alphanumeric + underscore
  if (trimmed.length < 4 || trimmed.length > 25) {
    throw new Error("Invalid username: must be between 4 and 25 characters");
  }

  // Check alphanumeric (allowing underscores)
  const withoutUnderscores = trimmed.replace(/_/g, "");
  if (!validator.isAlphanumeric(withoutUnderscores)) {
    throw new Error("Invalid username: must be alphanumeric with optional underscores");
  }

  return validator.escape(trimmed);
}

/**
 * Validates an email address
 * @param email - The email to validate
 * @returns True if valid
 */
export function isValidEmail(email: string): boolean {
  return validator.isEmail(email);
}

/**
 * Sanitizes a channel login parameter
 * Useful for query parameters and request bodies
 * @param channelLogin - The channel login to sanitize
 * @returns Sanitized channel login
 */
export function sanitizeChannelLogin(channelLogin: unknown): string {
  if (!channelLogin || typeof channelLogin !== "string") {
    throw new Error("Invalid channel login");
  }

  const sanitized = channelLogin.toString().toLowerCase().trim();

  if (!sanitized) {
    throw new Error("Channel login cannot be empty");
  }

  // Apply same validation as username
  return sanitizeUsername(sanitized);
}

/**
 * Validates and sanitizes a command name
 * @param command - The command name to validate
 * @param allowedCommands - List of allowed command names
 * @returns Sanitized command name
 * @throws Error if command is invalid or not allowed
 */
export function validateCommand(command: unknown, allowedCommands: string[]): string {
  if (!command || typeof command !== "string") {
    throw new Error("Invalid command");
  }

  const sanitized = command.trim().toLowerCase();

  if (!allowedCommands.includes(sanitized)) {
    throw new Error(`Command not allowed: ${sanitized}`);
  }

  return sanitized;
}

/**
 * Validates a boolean value from request body
 * @param value - The value to validate
 * @returns Boolean value
 * @throws Error if value is not a boolean
 */
export function validateBoolean(value: unknown): boolean {
  if (typeof value !== "boolean") {
    throw new Error("Value must be a boolean");
  }
  return value;
}

/**
 * Validates an auto-chat mode
 * @param mode - The mode to validate
 * @param validModes - Array of valid modes
 * @returns Validated mode
 * @throws Error if mode is invalid
 */
export function validateMode(mode: unknown, validModes: readonly string[]): string {
  if (!mode || typeof mode !== "string") {
    throw new Error("Invalid mode");
  }

  const sanitized = mode.toLowerCase().trim();

  if (!validModes.includes(sanitized)) {
    throw new Error(`Invalid mode: ${sanitized}. Must be one of: ${validModes.join(", ")}`);
  }

  return sanitized;
}
