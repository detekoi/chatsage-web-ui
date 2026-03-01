/**
 * Redaction utility for sanitizing sensitive data in logs.
 * Preserves enough information for debugging while hiding the full value.
 */

/**
 * Redacts a string, showing only the first few characters.
 * @param value - The value to redact
 * @param visibleChars - Number of characters to keep visible (default: 3)
 * @returns Redacted string, e.g. "hen***"
 */
export function redact(value: string, visibleChars = 3): string {
    if (!value) return "[empty]";
    if (value.length <= visibleChars) return "***";
    return value.slice(0, visibleChars) + "***";
}
