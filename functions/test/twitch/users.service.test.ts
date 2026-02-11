/**
 * Tests for twitch/users.service.ts
 * Twitch user lookup by username
 */

import axios from "axios";
import { getUserIdFromUsername } from "@/twitch/users.service";

jest.mock("axios");
jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

jest.mock("@/twitch/appToken.service", () => ({
    getAppAccessToken: jest.fn().mockResolvedValue("mock-app-token"),
}));

const mockAxios = axios as jest.Mocked<typeof axios>;

describe("getUserIdFromUsername", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it("returns user ID for a found user", async () => {
        mockAxios.get.mockResolvedValueOnce({
            data: {
                data: [{ id: "123456", login: "testuser", display_name: "TestUser" }],
            },
        });

        const userId = await getUserIdFromUsername("testuser");
        expect(userId).toBe("123456");
    });

    it("returns null when user is not found", async () => {
        mockAxios.get.mockResolvedValueOnce({
            data: { data: [] },
        });

        const userId = await getUserIdFromUsername("nonexistentuser");
        expect(userId).toBeNull();
    });

    it("returns null on API error", async () => {
        mockAxios.get.mockRejectedValueOnce(new Error("API Error"));

        const userId = await getUserIdFromUsername("testuser");
        expect(userId).toBeNull();
    });

    it("passes app access token in Authorization header", async () => {
        mockAxios.get.mockResolvedValueOnce({
            data: { data: [{ id: "789" }] },
        });

        await getUserIdFromUsername("testuser");

        expect(mockAxios.get).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({
                headers: expect.objectContaining({
                    Authorization: "Bearer mock-app-token",
                }),
            }),
        );
    });
});
