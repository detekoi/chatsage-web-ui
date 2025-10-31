/**
 * Winston logger configuration for structured logging
 * Provides consistent logging across all modules with request tracking
 */

import winston from "winston";

const IS_PRODUCTION = process.env.NODE_ENV === "production";
const IS_TEST = process.env.NODE_ENV === "test";

// Custom format for Cloud Functions logs
const cloudFunctionsFormat = winston.format.printf(({ level, message, timestamp, requestId, ...metadata }) => {
  let log = `[${timestamp}] ${level.toUpperCase()}`;

  if (requestId) {
    log += ` [${requestId}]`;
  }

  log += `: ${message}`;

  // Append metadata if present
  if (Object.keys(metadata).length > 0) {
    log += ` ${JSON.stringify(metadata)}`;
  }

  return log;
});

// Create the Winston logger
export const logger = winston.createLogger({
  level: IS_PRODUCTION ? "info" : "debug",
  silent: IS_TEST, // Silence logs during tests
  format: winston.format.combine(
    winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    cloudFunctionsFormat,
  ),
  transports: [
    new winston.transports.Console({
      stderrLevels: ["error"],
    }),
  ],
});

/**
 * Creates a child logger with a specific context
 * @param context - Context identifier (e.g., "OAuth", "TokenRefresh")
 * @returns Child logger instance
 */
export function createChildLogger(context: string) {
  return logger.child({ context });
}

/**
 * Middleware to add request ID tracking to Express requests
 */
export function requestIdMiddleware(req: any, res: any, next: any) {
  const requestId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  req.requestId = requestId;

  // Add request ID to all logs made during this request
  req.logger = logger.child({ requestId });

  next();
}

// Export convenience methods for backward compatibility with console.log
export const log = {
  info: (message: string, ...args: any[]) => logger.info(message, ...args),
  error: (message: string, ...args: any[]) => logger.error(message, ...args),
  warn: (message: string, ...args: any[]) => logger.warn(message, ...args),
  debug: (message: string, ...args: any[]) => logger.debug(message, ...args),
};
