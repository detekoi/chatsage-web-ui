/**
 * Jest test setup file
 * Runs before all tests to configure the test environment
 */

import type { Server } from "node:http";
import { Test } from "supertest";

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

/*
 * Bind supertest's per-request server to 127.0.0.1.
 *
 * supertest starts the app with `listen(0)`, which binds every interface, then connects to
 * 127.0.0.1:<port>. On macOS another process can hold 127.0.0.1 on that same port, and its more
 * specific bind takes the connection, so a test gets a 401, 403 or 200 from an unrelated local
 * server. Binding to 127.0.0.1 makes the OS pick a port that is free there. Passing a host makes
 * listen() asynchronous, so the URL is filled in once the server is listening.
 */
const LOOPBACK = "127.0.0.1";
type PendingTest = {
  _server?: Server;
  _loopbackPath?: string;
  url: string;
  end(fn?: (err: unknown, res?: unknown) => void): unknown;
};
const testProto = Test.prototype as unknown as PendingTest & {
  serverAddress(app: Server, path: string): string;
};
const serverAddress = testProto.serverAddress;
const end = testProto.end;
testProto.serverAddress = function(this: PendingTest, app: Server, path: string) {
  if (app.address()) return serverAddress.call(this, app, path);
  this._server = app.listen(0, LOOPBACK);
  this._loopbackPath = path;
  return path;
};
testProto.end = function(this: PendingTest, fn) {
  const server = this._server;
  const path = this._loopbackPath;
  if (!server || path === undefined) return end.call(this, fn);
  this._loopbackPath = undefined;
  const send = () => {
    const address = server.address();
    this.url = `http://${LOOPBACK}:${typeof address === "object" && address ? address.port : 0}${path}`;
    end.call(this, fn);
  };
  if (server.listening) send();
  else {
    server.once("listening", send);
    server.once("error", (err) => fn?.(err));
  }
  return this;
};

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
