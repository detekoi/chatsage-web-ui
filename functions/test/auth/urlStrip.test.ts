/**
 * Tests for the credential-stripping script in the head of auth-complete.html.
 *
 * It exists so the analytics tag below it never sees a credential in the URL.
 * That only holds if it strips whatever the callback actually sends, so this
 * runs the real script out of the real file rather than a copy — the two drifted
 * apart once already, when the callback moved from `session_token` to `code`.
 */

import fs from "fs";
import path from "path";

const PAGE = path.join(__dirname, "../../../public/auth-complete.html");

/**
 * Pulls the head strip script out of the page and runs it against a URL.
 * @param search - The query string the callback would land with
 * @return The rewritten URL and anything handed over in memory
 */
function runStrip(search: string) {
  const html = fs.readFileSync(PAGE, "utf8");

  const inlineScripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)]
    .map((m) => m[1]);
  const strip = inlineScripts.find((s) => s.includes("history.replaceState") && s.includes("params.delete"));

  if (!strip) throw new Error("No credential-stripping script found in auth-complete.html");

  let rewritten: string | null = null;
  const win = {
    location: { search, pathname: "/auth-complete.html", hash: "" },
    history: { replaceState: (_s: unknown, _t: unknown, url: string) => { rewritten = url; } },
  } as Record<string, unknown>;

  new Function("window", "URLSearchParams", strip)(win, URLSearchParams);

  return {
    url: rewritten,
    sessionToken: win.__sessionToken as string | undefined,
    exchangeCode: win.__exchangeCode as string | undefined,
  };
}

describe("auth-complete.html credential stripping", () => {
  it("takes the exchange code out of the URL and hands it over in memory", () => {
    const result = runStrip("?user_login=bob&user_id=42&state=abc&code=" + "a".repeat(64));

    expect(result.exchangeCode).toBe("a".repeat(64));
    expect(result.url).not.toContain("code=");
  });

  it("still handles the legacy session_token shape", () => {
    const result = runStrip("?user_login=bob&user_id=42&session_token=SECRET.JWT");

    expect(result.sessionToken).toBe("SECRET.JWT");
    expect(result.url).not.toContain("SECRET");
  });

  it("keeps the non-secret parameters", () => {
    const result = runStrip("?user_login=bob&user_id=42&state=abc&code=" + "a".repeat(64));

    expect(result.url).toContain("user_login=bob");
    expect(result.url).toContain("user_id=42");
    expect(result.url).toContain("state=abc");
  });

  it("leaves the URL alone when there is no credential to strip", () => {
    const result = runStrip("?user_login=bob");

    expect(result.url).toBeNull();
  });

  it("strips both shapes if both somehow arrive", () => {
    const result = runStrip("?code=" + "a".repeat(64) + "&session_token=SECRET.JWT");

    expect(result.exchangeCode).toBe("a".repeat(64));
    expect(result.sessionToken).toBe("SECRET.JWT");
    expect(result.url).not.toContain("code=");
    expect(result.url).not.toContain("SECRET");
  });

  it("runs before the analytics loader in the page", () => {
    const html = fs.readFileSync(PAGE, "utf8");

    // Referer on the analytics request is taken from the URL as it stands when
    // the request goes out, so the strip has to come first in document order.
    expect(html.indexOf("history.replaceState")).toBeLessThan(html.indexOf("rybbit"));
  });
});
