/**
 * Tests for utils/secrets.ts
 * Secret Manager utilities with caching
 */

import {
    normalizeSecretVersionPath,
    getSecret,
    getAllowedChannelsList,
    clearSecretCache,
} from "@/utils/secrets";

// Mock dependencies
jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

jest.mock("@/config/constants", () => ({
    ALLOWED_CHANNELS_SECRET_NAME: "projects/p/secrets/allowed-channels",
    WEBUI_INTERNAL_TOKEN: "test-internal-token",
}));

const mockAccessSecretVersion = jest.fn();
const mockGetSecret = jest.fn();
const mockCreateSecret = jest.fn();
const mockAddSecretVersion = jest.fn();

jest.mock("@/config/database", () => ({
    getSecretManager: () => ({
        accessSecretVersion: mockAccessSecretVersion,
        getSecret: mockGetSecret,
        createSecret: mockCreateSecret,
        addSecretVersion: mockAddSecretVersion,
    }),
    getProjectId: () => "test-project",
}));

describe("normalizeSecretVersionPath", () => {
    it("adds /versions/latest to a bare secret path", () => {
        expect(normalizeSecretVersionPath("projects/my-proj/secrets/my-secret")).toBe(
            "projects/my-proj/secrets/my-secret/versions/latest",
        );
    });

    it("returns the path unchanged if it already has a version", () => {
        const path = "projects/my-proj/secrets/my-secret/versions/3";
        expect(normalizeSecretVersionPath(path)).toBe(path);
    });

    it("throws for empty input", () => {
        expect(() => normalizeSecretVersionPath("")).toThrow("secretInput is empty");
    });
});

describe("getSecret", () => {
    beforeEach(() => {
        jest.clearAllMocks();
        clearSecretCache();
    });

    it("fetches a secret from Secret Manager (string payload)", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: "my-secret-value" } },
        ]);

        const result = await getSecret("projects/p/secrets/s");
        expect(result).toBe("my-secret-value");
    });

    it("handles Buffer payload", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: Buffer.from("buffer-value", "utf8") } },
        ]);

        const result = await getSecret("projects/p/secrets/s");
        expect(result).toBe("buffer-value");
    });

    it("handles Uint8Array payload", async () => {
        const bytes = new Uint8Array(Buffer.from("uint8-value", "utf8"));
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: bytes } },
        ]);

        const result = await getSecret("projects/p/secrets/s");
        expect(result).toBe("uint8-value");
    });

    it("returns cached value on second call", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: "cached-value" } },
        ]);

        await getSecret("projects/p/secrets/s");
        const result = await getSecret("projects/p/secrets/s");

        expect(result).toBe("cached-value");
        // Only called once — second call used cache
        expect(mockAccessSecretVersion).toHaveBeenCalledTimes(1);
    });

    it("bypasses cache when useCache is false", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: "value" } },
        ]);

        await getSecret("projects/p/secrets/s", true);
        await getSecret("projects/p/secrets/s", false);

        expect(mockAccessSecretVersion).toHaveBeenCalledTimes(2);
    });

    it("throws when Secret Manager call fails", async () => {
        mockAccessSecretVersion.mockRejectedValue(new Error("Permission denied"));

        await expect(getSecret("projects/p/secrets/s")).rejects.toThrow(
            "Failed to fetch secret",
        );
    });
});

describe("getAllowedChannelsList", () => {
    beforeEach(() => {
        jest.clearAllMocks();
        clearSecretCache();
    });
    it("parses CSV data into an array of lowercase channel names", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: "Channel1, channel2, CHANNEL3" } },
        ]);

        const result = await getAllowedChannelsList();
        expect(result).toEqual(["channel1", "channel2", "channel3"]);
    });

    it("filters out empty entries", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: "ch1,,ch2, ,ch3" } },
        ]);

        const result = await getAllowedChannelsList();
        expect(result).toEqual(["ch1", "ch2", "ch3"]);
    });

    it("returns empty array when secret data is empty", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: "  " } },
        ]);

        const result = await getAllowedChannelsList();
        expect(result).toEqual([]);
    });

    it("returns empty array when secret fetch fails", async () => {
        mockAccessSecretVersion.mockRejectedValue(new Error("Secret not found"));

        const result = await getAllowedChannelsList();
        expect(result).toEqual([]);
    });
});

describe("clearSecretCache", () => {
    beforeEach(() => {
        jest.clearAllMocks();
        clearSecretCache();
    });

    it("clears the cache so subsequent calls fetch fresh data", async () => {
        mockAccessSecretVersion.mockResolvedValue([
            { payload: { data: "value" } },
        ]);

        await getSecret("projects/p/secrets/s");
        expect(mockAccessSecretVersion).toHaveBeenCalledTimes(1);

        clearSecretCache();

        await getSecret("projects/p/secrets/s");
        expect(mockAccessSecretVersion).toHaveBeenCalledTimes(2);
    });
});
