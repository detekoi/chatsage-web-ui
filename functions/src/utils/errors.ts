/**
 * Error handling utilities
 * Provides safe error responses and redirects
 */

import { Response } from "express";
import { FRONTEND_URL_CONFIG } from "@/config/constants";
import { logger } from "@/config/logger";

/**
 * Redirects to frontend error page with error details
 * @param res - Express response object
 * @param errorCode - Error code for categorization
 * @param errorMessage - User-friendly error message
 * @param twitchQueryState - Optional Twitch OAuth state for redirect preservation
 */
export function redirectToFrontendWithError(
  res: Response,
  errorCode: string,
  errorMessage: string,
  twitchQueryState?: string | null,
) {
  let errorUrl: URL;

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
  } catch (urlError: any) {
    logger.error("Error constructing error redirect URL", {
      error: urlError.message,
    });
    return res.status(500).send("Authentication failed and unable to construct error redirect.");
  }

  logger.error(`Redirecting to error page: ${errorUrl.toString()}`, {
    errorCode,
    errorMessage,
  });

  return res.redirect(errorUrl.toString());
}

/**
 * Sanitizes error details for client response
 * Prevents exposing internal error details in production
 * @param error - The error object
 * @param defaultMessage - Default user-friendly message
 * @returns Sanitized error message
 */
export function sanitizeErrorMessage(error: any, defaultMessage: string): string {
  // In production, never expose internal error details
  if (process.env.NODE_ENV === "production") {
    return defaultMessage;
  }

  // In development, provide more details for debugging
  return error?.message || defaultMessage;
}

/**
 * Handles API errors with consistent response format
 * @param res - Express response object
 * @param error - The error object
 * @param defaultMessage - Default user-friendly message
 * @param statusCode - HTTP status code (default: 500)
 */
export function handleApiError(
  res: Response,
  error: any,
  defaultMessage: string,
  statusCode = 500,
) {
  const message = sanitizeErrorMessage(error, defaultMessage);

  logger.error("API error", {
    message,
    error: error?.message,
    stack: error?.stack,
    statusCode,
  });

  res.status(statusCode).json({
    success: false,
    message,
  });
}

/**
 * Determines if an error indicates a need for re-authentication
 * @param error - The error object or message
 * @returns True if user needs to re-authenticate
 */
export function needsReAuth(error: any): boolean {
  const errorMessage = typeof error === "string" ? error : error?.message || "";

  return (
    errorMessage.includes("re-authenticate") ||
    errorMessage.includes("Refresh token not available") ||
    errorMessage.includes("User not found") ||
    errorMessage.includes("invalid") ||
    errorMessage.includes("expired")
  );
}

/**
 * Custom error class for authentication errors
 */
export class AuthError extends Error {
  constructor(message: string, public statusCode: number = 401) {
    super(message);
    this.name = "AuthError";
  }
}

/**
 * Custom error class for validation errors
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/**
 * Custom error class for Twitch API errors
 */
export class TwitchApiError extends Error {
  constructor(message: string, public statusCode?: number, public twitchError?: any) {
    super(message);
    this.name = "TwitchApiError";
  }
}
