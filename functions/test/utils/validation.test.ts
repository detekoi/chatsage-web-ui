/**
 * Tests for utils/validation.ts
 * Input validation and sanitization utilities
 */

import {
    sanitizeUsername,
    sanitizeChannelLogin,
    isValidEmail,
    validateCommand,
    validateBoolean,
    validateMode,
} from "@/utils/validation";

describe("sanitizeUsername", () => {
    it("accepts valid Twitch usernames", () => {
        expect(sanitizeUsername("testuser")).toBe("testuser");
        expect(sanitizeUsername("Test_User")).toBe("test_user");
        expect(sanitizeUsername("user1234")).toBe("user1234");
    });

    it("trims and lowercases input", () => {
        expect(sanitizeUsername("  TestUser  ")).toBe("testuser");
        expect(sanitizeUsername("ALLCAPS")).toBe("allcaps");
    });

    it("accepts usernames at length boundaries", () => {
        // 4 chars (minimum)
        expect(sanitizeUsername("abcd")).toBe("abcd");
        // 25 chars (maximum)
        const maxName = "a".repeat(25);
        expect(sanitizeUsername(maxName)).toBe(maxName);
    });

    it("throws for usernames that are too short", () => {
        expect(() => sanitizeUsername("abc")).toThrow("must be between 4 and 25 characters");
    });

    it("throws for usernames that are too long", () => {
        const longName = "a".repeat(26);
        expect(() => sanitizeUsername(longName)).toThrow("must be between 4 and 25 characters");
    });

    it("throws for empty/null/undefined inputs", () => {
        expect(() => sanitizeUsername("")).toThrow("must be a non-empty string");
        expect(() => sanitizeUsername(null)).toThrow("must be a non-empty string");
        expect(() => sanitizeUsername(undefined)).toThrow("must be a non-empty string");
    });

    it("throws for non-string inputs", () => {
        expect(() => sanitizeUsername(12345)).toThrow("must be a non-empty string");
        expect(() => sanitizeUsername(true)).toThrow("must be a non-empty string");
        expect(() => sanitizeUsername({})).toThrow("must be a non-empty string");
    });

    it("throws for usernames with special characters", () => {
        expect(() => sanitizeUsername("user@name")).toThrow("must be alphanumeric");
        expect(() => sanitizeUsername("user name")).toThrow("must be alphanumeric");
        expect(() => sanitizeUsername("user!name")).toThrow("must be alphanumeric");
        expect(() => sanitizeUsername("user.name")).toThrow("must be alphanumeric");
    });

    it("allows underscores in usernames", () => {
        expect(sanitizeUsername("test_user_1")).toBe("test_user_1");
        expect(sanitizeUsername("__test__")).toBe("__test__");
    });
});

describe("sanitizeChannelLogin", () => {
    it("sanitizes valid channel login", () => {
        expect(sanitizeChannelLogin("testchannel")).toBe("testchannel");
        expect(sanitizeChannelLogin("Test_Channel")).toBe("test_channel");
    });

    it("trims and lowercases", () => {
        expect(sanitizeChannelLogin("  TestChannel  ")).toBe("testchannel");
    });

    it("throws for empty/null/undefined inputs", () => {
        expect(() => sanitizeChannelLogin("")).toThrow("Invalid channel login");
        expect(() => sanitizeChannelLogin(null)).toThrow("Invalid channel login");
        expect(() => sanitizeChannelLogin(undefined)).toThrow("Invalid channel login");
    });

    it("throws for non-string inputs", () => {
        expect(() => sanitizeChannelLogin(12345)).toThrow("Invalid channel login");
    });

    it("delegates validation to sanitizeUsername (rejects invalid names)", () => {
        expect(() => sanitizeChannelLogin("ab")).toThrow(); // too short
        expect(() => sanitizeChannelLogin("user@name")).toThrow(); // special chars
    });
});

describe("isValidEmail", () => {
    it("returns true for valid emails", () => {
        expect(isValidEmail("user@example.com")).toBe(true);
        expect(isValidEmail("test.user+tag@domain.co")).toBe(true);
    });

    it("returns false for invalid emails", () => {
        expect(isValidEmail("not-an-email")).toBe(false);
        expect(isValidEmail("@missing-local.com")).toBe(false);
        expect(isValidEmail("missing-at-sign")).toBe(false);
        expect(isValidEmail("")).toBe(false);
    });
});

describe("validateCommand", () => {
    const allowedCommands = ["ask", "search", "game", "help"];

    it("returns sanitized command name for allowed commands", () => {
        expect(validateCommand("ask", allowedCommands)).toBe("ask");
        expect(validateCommand("  ASK  ", allowedCommands)).toBe("ask");
        expect(validateCommand("Search", allowedCommands)).toBe("search");
    });

    it("throws for commands not in the allowed list", () => {
        expect(() => validateCommand("delete", allowedCommands)).toThrow("Command not allowed: delete");
    });

    it("throws for empty/null/undefined inputs", () => {
        expect(() => validateCommand("", allowedCommands)).toThrow("Invalid command");
        expect(() => validateCommand(null, allowedCommands)).toThrow("Invalid command");
        expect(() => validateCommand(undefined, allowedCommands)).toThrow("Invalid command");
    });

    it("throws for non-string inputs", () => {
        expect(() => validateCommand(123, allowedCommands)).toThrow("Invalid command");
        expect(() => validateCommand(true, allowedCommands)).toThrow("Invalid command");
    });
});

describe("validateBoolean", () => {
    it("returns the boolean value for valid booleans", () => {
        expect(validateBoolean(true)).toBe(true);
        expect(validateBoolean(false)).toBe(false);
    });

    it("throws for non-boolean values", () => {
        expect(() => validateBoolean("true")).toThrow("Value must be a boolean");
        expect(() => validateBoolean(1)).toThrow("Value must be a boolean");
        expect(() => validateBoolean(null)).toThrow("Value must be a boolean");
        expect(() => validateBoolean(undefined)).toThrow("Value must be a boolean");
        expect(() => validateBoolean({})).toThrow("Value must be a boolean");
    });
});

describe("validateMode", () => {
    const validModes = ["off", "low", "medium", "high"] as const;

    it("returns sanitized mode for valid modes", () => {
        expect(validateMode("off", validModes)).toBe("off");
        expect(validateMode("LOW", validModes)).toBe("low");
        expect(validateMode("  Medium  ", validModes)).toBe("medium");
        expect(validateMode("HIGH", validModes)).toBe("high");
    });

    it("throws for invalid modes", () => {
        expect(() => validateMode("extreme", validModes)).toThrow(
            "Invalid mode: extreme. Must be one of: off, low, medium, high",
        );
    });

    it("throws for empty/null/undefined inputs", () => {
        expect(() => validateMode("", validModes)).toThrow("Invalid mode");
        expect(() => validateMode(null, validModes)).toThrow("Invalid mode");
        expect(() => validateMode(undefined, validModes)).toThrow("Invalid mode");
    });

    it("throws for non-string inputs", () => {
        expect(() => validateMode(123, validModes)).toThrow("Invalid mode");
    });
});
