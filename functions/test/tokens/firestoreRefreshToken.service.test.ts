/**
 * Tests for tokens/firestoreRefreshToken.service.ts
 * Firestore-backed per-user OAuth token storage
 */

import {
    getStoredTwitchRefreshToken,
    storeTwitchRefreshToken,
} from "@/tokens/firestoreRefreshToken.service";

jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

jest.mock("@/config/database", () => ({
    FieldValue: { serverTimestamp: () => "SERVER_TIMESTAMP" },
}));

// Build a mock Firestore
function createMockDb(docData: Record<string, unknown> | undefined = undefined) {
    const mockSet = jest.fn().mockResolvedValue(undefined);
    const mockGet = jest.fn().mockResolvedValue({
        data: () => docData,
    });

    const db = {
        collection: jest.fn().mockReturnValue({
            doc: jest.fn().mockReturnValue({
                collection: jest.fn().mockReturnValue({
                    doc: jest.fn().mockReturnValue({
                        get: mockGet,
                        set: mockSet,
                    }),
                }),
            }),
        }),
        _mockGet: mockGet,
        _mockSet: mockSet,
    };

    return db;
}

describe("getStoredTwitchRefreshToken", () => {
    it("returns the stored refresh token", async () => {
        const db = createMockDb({ twitchRefreshToken: "stored-token" });
        const result = await getStoredTwitchRefreshToken(db as any, "user-123");
        expect(result).toBe("stored-token");
    });

    it("returns null when no document data exists", async () => {
        const db = createMockDb(undefined);
        const result = await getStoredTwitchRefreshToken(db as any, "user-123");
        expect(result).toBeNull();
    });

    it("returns null when token field is missing", async () => {
        const db = createMockDb({ otherField: "value" });
        const result = await getStoredTwitchRefreshToken(db as any, "user-123");
        expect(result).toBeNull();
    });

    it("returns null when token is not a string", async () => {
        const db = createMockDb({ twitchRefreshToken: 12345 });
        const result = await getStoredTwitchRefreshToken(db as any, "user-123");
        expect(result).toBeNull();
    });
});

describe("storeTwitchRefreshToken", () => {
    it("stores token with merge and basic metadata", async () => {
        const db = createMockDb();
        await storeTwitchRefreshToken(db as any, "user-123", "new-token");

        expect(db._mockSet).toHaveBeenCalledWith(
            expect.objectContaining({
                twitchRefreshToken: "new-token",
                updatedAt: "SERVER_TIMESTAMP",
            }),
            { merge: true },
        );
    });

    it("includes migratedFrom metadata when provided", async () => {
        const db = createMockDb();
        await storeTwitchRefreshToken(db as any, "user-123", "token", {
            migratedFrom: "secret-manager",
        });

        expect(db._mockSet).toHaveBeenCalledWith(
            expect.objectContaining({
                migratedFrom: "secret-manager",
            }),
            { merge: true },
        );
    });

    it("includes reason metadata when provided", async () => {
        const db = createMockDb();
        await storeTwitchRefreshToken(db as any, "user-123", "token", {
            reason: "twitch-rotation",
        });

        expect(db._mockSet).toHaveBeenCalledWith(
            expect.objectContaining({
                updateReason: "twitch-rotation",
            }),
            { merge: true },
        );
    });
});
