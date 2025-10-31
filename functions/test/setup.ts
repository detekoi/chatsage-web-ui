/**
 * Jest test setup file
 * Runs before all tests to configure the test environment
 */

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.GCLOUD_PROJECT = 'test-project';
process.env.TWITCH_CLIENT_ID = 'test-client-id';
process.env.TWITCH_CLIENT_SECRET = 'test-client-secret';
process.env.JWT_SECRET_KEY = 'test-jwt-secret';
process.env.FRONTEND_URL = 'http://localhost:5002';
process.env.CALLBACK_URL = 'http://localhost:5001/webUi/auth/twitch/callback';
process.env.BOT_PUBLIC_URL = 'http://localhost:3000';
process.env.TWITCH_EVENTSUB_SECRET = 'test-eventsub-secret';
process.env.TWITCH_BOT_USERNAME = 'testbot';

// Increase test timeout for integration tests
jest.setTimeout(10000);

// Mock console methods to reduce noise in test output
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  // Keep error for debugging test failures
  error: console.error,
};
