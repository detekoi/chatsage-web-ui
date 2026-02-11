/**
 * Tests for internal/authentication.middleware.ts
 * Internal bot request authentication
 */

import { authenticateInternalRequest } from "@/internal/authentication.middleware";

// Mock dependencies
jest.mock("@/config/logger", () => ({
    logger: {
        error: jest.fn(),
        warn: jest.fn(),
        info: jest.fn(),
        debug: jest.fn(),
    },
}));

jest.mock("@/utils/secrets", () => ({
    getInternalBotTokenValue: jest.fn(),
}));

import { getInternalBotTokenValue } from "@/utils/secrets";
const mockGetToken = getInternalBotTokenValue as jest.MockedFunction<typeof getInternalBotTokenValue>;

describe("authenticateInternalRequest", () => {
    let mockReq: any;
    let mockRes: any;
    let mockNext: jest.Mock;

    beforeEach(() => {
        mockReq = {
            headers: {},
            path: "/internal/test",
        };
        mockRes = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn(),
        };
        mockNext = jest.fn();
        jest.clearAllMocks();
    });

    it("returns 401 when no Authorization header is present", async () => {
        await authenticateInternalRequest(mockReq, mockRes, mockNext);
        expect(mockRes.status).toHaveBeenCalledWith(401);
        expect(mockRes.json).toHaveBeenCalledWith({
            success: false,
            message: "Unauthorized: Missing token",
        });
        expect(mockNext).not.toHaveBeenCalled();
    });

    it("returns 401 for non-Bearer authorization", async () => {
        mockReq.headers.authorization = "Basic abc123";
        await authenticateInternalRequest(mockReq, mockRes, mockNext);
        expect(mockRes.status).toHaveBeenCalledWith(401);
        expect(mockNext).not.toHaveBeenCalled();
    });

    it("returns 401 when token does not match expected value", async () => {
        mockGetToken.mockResolvedValue("correct-token");
        mockReq.headers.authorization = "Bearer wrong-token";

        await authenticateInternalRequest(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(401);
        expect(mockRes.json).toHaveBeenCalledWith({
            success: false,
            message: "Unauthorized: Invalid token",
        });
        expect(mockNext).not.toHaveBeenCalled();
    });

    it("calls next when token matches expected value", async () => {
        mockGetToken.mockResolvedValue("valid-internal-token");
        mockReq.headers.authorization = "Bearer valid-internal-token";

        await authenticateInternalRequest(mockReq, mockRes, mockNext);

        expect(mockNext).toHaveBeenCalled();
        expect(mockRes.status).not.toHaveBeenCalled();
    });

    it("returns 500 when secret fetch fails", async () => {
        mockGetToken.mockRejectedValue(new Error("Secret Manager error"));
        mockReq.headers.authorization = "Bearer some-token";

        await authenticateInternalRequest(mockReq, mockRes, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(500);
        expect(mockRes.json).toHaveBeenCalledWith({
            success: false,
            message: "Internal server error",
        });
        expect(mockNext).not.toHaveBeenCalled();
    });
});
