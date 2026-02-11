/**
 * Tests for config/database.ts
 * Firestore and Secret Manager initialization
 */

// We need to test the module isolation, so we use resetModules
// and dynamic require for each test case

jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

describe("getProjectId", () => {
    let getProjectId: () => string;

    beforeEach(() => {
        jest.resetModules();
    });

    it("returns project ID from GCLOUD_PROJECT env var", () => {
        process.env.GCLOUD_PROJECT = "my-test-project";
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const db = require("@/config/database");
        getProjectId = db.getProjectId;

        expect(getProjectId()).toBe("my-test-project");

        delete process.env.GCLOUD_PROJECT;
    });

    it("returns project ID from GCP_PROJECT env var", () => {
        delete process.env.GCLOUD_PROJECT;
        process.env.GCP_PROJECT = "another-project";
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const db = require("@/config/database");
        getProjectId = db.getProjectId;

        expect(getProjectId()).toBe("another-project");

        delete process.env.GCP_PROJECT;
    });
});

describe("getDb", () => {
    it("throws when database is not initialized", () => {
        jest.resetModules();
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { getDb } = require("@/config/database");
        expect(() => getDb()).toThrow();
    });
});

describe("getSecretManager", () => {
    it("throws when Secret Manager is not initialized", () => {
        jest.resetModules();
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const { getSecretManager } = require("@/config/database");
        expect(() => getSecretManager()).toThrow();
    });
});
