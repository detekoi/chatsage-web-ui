/**
 * Tests for tokens/cache.service.ts
 * In-memory token caching service
 */

import {
    getCachedToken,
    cacheToken,
    clearCachedToken,
    clearAllCachedTokens,
    getCacheStats,
} from "@/tokens/cache.service";

// Mock dependencies
jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

describe("Token Cache Service", () => {
    beforeEach(() => {
        clearAllCachedTokens();
    });

    describe("cacheToken + getCachedToken", () => {
        it("stores a token and retrieves it", () => {
            cacheToken("testuser", "access-token-123", 3600);
            const result = getCachedToken("testuser");
            expect(result).toBe("access-token-123");
        });

        it("returns null for a non-existent user", () => {
            expect(getCachedToken("unknownuser")).toBeNull();
        });

        it("returns null for an expired token", () => {
            // Cache with 0 seconds expiry (already expired after buffer subtraction)
            cacheToken("testuser", "expired-token", 0);
            expect(getCachedToken("testuser")).toBeNull();
        });

        it("properly respects the cache buffer (TOKEN_CACHE_BUFFER_SECONDS = 300)", () => {
            // Cache with exactly the buffer seconds — should be expired immediately
            cacheToken("testuser", "token", 300);
            expect(getCachedToken("testuser")).toBeNull();

            // Cache with more than the buffer — should be valid
            cacheToken("testuser2", "token2", 600);
            expect(getCachedToken("testuser2")).toBe("token2");
        });
    });

    describe("clearCachedToken", () => {
        it("removes a specific cached token", () => {
            cacheToken("user1", "token1", 3600);
            cacheToken("user2", "token2", 3600);

            clearCachedToken("user1");

            expect(getCachedToken("user1")).toBeNull();
            expect(getCachedToken("user2")).toBe("token2");
        });

        it("does not throw for non-existent user", () => {
            expect(() => clearCachedToken("nonexistent")).not.toThrow();
        });
    });

    describe("clearAllCachedTokens", () => {
        it("empties the entire cache", () => {
            cacheToken("user1", "token1", 3600);
            cacheToken("user2", "token2", 3600);

            clearAllCachedTokens();

            expect(getCachedToken("user1")).toBeNull();
            expect(getCachedToken("user2")).toBeNull();
            expect(getCacheStats().size).toBe(0);
        });
    });

    describe("getCacheStats", () => {
        it("returns the correct cache size", () => {
            expect(getCacheStats().size).toBe(0);

            cacheToken("user1", "token1", 3600);
            expect(getCacheStats().size).toBe(1);

            cacheToken("user2", "token2", 3600);
            expect(getCacheStats().size).toBe(2);
        });

        it("returns the cached entry keys", () => {
            cacheToken("alpha", "t1", 3600);
            cacheToken("bravo", "t2", 3600);

            const stats = getCacheStats();
            expect(stats.entries).toContain("alpha");
            expect(stats.entries).toContain("bravo");
        });
    });
});
