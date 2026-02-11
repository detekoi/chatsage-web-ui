/**
 * Tests for twitch/moderators.service.ts
 * Adding moderators to Twitch channels
 */

import axios from "axios";
import { addModerator } from "@/twitch/moderators.service";

jest.mock("axios");
jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

jest.mock("@/tokens/token.service", () => ({
    getValidTwitchTokenForUser: jest.fn().mockResolvedValue("mock-access-token"),
}));

const mockAxios = axios as jest.Mocked<typeof axios>;

describe("addModerator", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it("returns success when Twitch returns 204", async () => {
        mockAxios.post.mockResolvedValueOnce({ status: 204 });

        const result = await addModerator("broadcaster_login", "broadcaster-id", "user-id");
        expect(result).toEqual({ success: true });
    });

    it("returns success when user is already a moderator (400)", async () => {
        mockAxios.post.mockRejectedValueOnce({
            response: {
                status: 400,
                data: { message: "user is already a moderator" },
            },
            message: "Bad Request",
        });

        const result = await addModerator("broadcaster_login", "broadcaster-id", "user-id");
        expect(result).toEqual({ success: true });
    });

    it("returns error for 401 unauthorized", async () => {
        mockAxios.post.mockRejectedValueOnce({
            response: {
                status: 401,
                data: { message: "Invalid OAuth token" },
            },
            message: "Unauthorized",
        });

        const result = await addModerator("broadcaster_login", "broadcaster-id", "user-id");
        expect(result.success).toBe(false);
        expect(result.error).toContain("re-authenticate");
    });

    it("returns error for 403 forbidden (missing scope)", async () => {
        mockAxios.post.mockRejectedValueOnce({
            response: {
                status: 403,
                data: { message: "Missing scope" },
            },
            message: "Forbidden",
        });

        const result = await addModerator("broadcaster_login", "broadcaster-id", "user-id");
        expect(result.success).toBe(false);
        expect(result.error).toContain("channel:manage:moderators");
    });

    it("returns error for 404 not found", async () => {
        mockAxios.post.mockRejectedValueOnce({
            response: {
                status: 404,
                data: { message: "Not Found" },
            },
            message: "Not Found",
        });

        const result = await addModerator("broadcaster_login", "broadcaster-id", "user-id");
        expect(result.success).toBe(false);
        expect(result.error).toContain("not found");
    });

    it("returns error for generic failures", async () => {
        mockAxios.post.mockRejectedValueOnce({
            response: { status: 500, data: { message: "Internal Server Error" } },
            message: "Server error",
        });

        const result = await addModerator("broadcaster_login", "broadcaster-id", "user-id");
        expect(result.success).toBe(false);
        expect(result.error).toBeDefined();
    });
});
