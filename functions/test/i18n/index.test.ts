/**
 * The dashboard renders an API response's `message` straight into a toast, so a response built in
 * English shows up as an English toast in an otherwise translated UI. These cover the resolution
 * and fallback rules that keep that from happening — and that keep an unknown locale harmless.
 */

import { Request, Response, NextFunction } from "express";
import {
  translate,
  resolveLocale,
  localeMiddleware,
  tr,
  DEFAULT_LOCALE,
  SUPPORTED_LOCALES,
} from "@/i18n";
import { catalogs } from "@/i18n/catalog";

describe("resolveLocale", () => {
  it("accepts every supported locale", () => {
    for (const locale of SUPPORTED_LOCALES) {
      expect(resolveLocale(locale)).toBe(locale);
    }
  });

  it("matches on the base language of a region subtag", () => {
    expect(resolveLocale("pt-BR")).toBe("pt");
    expect(resolveLocale("es_MX")).toBe("es");
    expect(resolveLocale("JA")).toBe("ja");
  });

  it("falls back to the default for anything unrecognized", () => {
    expect(resolveLocale("klingon")).toBe(DEFAULT_LOCALE);
    expect(resolveLocale("")).toBe(DEFAULT_LOCALE);
    expect(resolveLocale(undefined)).toBe(DEFAULT_LOCALE);
    expect(resolveLocale(null)).toBe(DEFAULT_LOCALE);
    expect(resolveLocale(42)).toBe(DEFAULT_LOCALE);
  });
});

describe("translate", () => {
  const knownKey = Object.keys(catalogs.en)[0];

  it("returns the catalog text for a translated key", () => {
    const translated = translate(knownKey, {}, catalogs.en[knownKey], "es");
    expect(translated).toBe(catalogs.es[knownKey]);
    expect(translated).not.toBe(catalogs.en[knownKey]);
  });

  it("returns the English fallback for an unknown key", () => {
    expect(translate("no.such.key", {}, "Fallback text", "es")).toBe("Fallback text");
  });

  it("returns the English fallback for an uncatalogued locale", () => {
    expect(translate(knownKey, {}, "Fallback text", "th")).toBe("Fallback text");
  });

  it("interpolates placeholders", () => {
    expect(translate("no.such.key", { name: "hello" }, "Command !{name} saved.", "en"))
      .toBe("Command !hello saved.");
  });

  it("leaves a placeholder alone when its value is missing, rather than printing undefined", () => {
    const out = translate("no.such.key", {}, "Command !{name} saved.", "en");
    expect(out).toContain("{name}");
    expect(out).not.toContain("undefined");
  });
});

describe("localeMiddleware", () => {
  const run = (header?: string) => {
    const req = { get: (h: string) => (h === "X-Locale" ? header : undefined) } as unknown as Request;
    const next = jest.fn() as NextFunction;
    localeMiddleware(req, {} as Response, next);
    return { req, next };
  };

  it("attaches the locale from the X-Locale header", () => {
    const { req, next } = run("ja");
    expect(req.locale).toBe("ja");
    expect(next).toHaveBeenCalled();
  });

  it("defaults when the header is absent", () => {
    expect(run().req.locale).toBe(DEFAULT_LOCALE);
  });

  it("makes tr() use the resolved locale", () => {
    const knownKey = Object.keys(catalogs.en)[0];
    const { req } = run("de");
    expect(tr(req, knownKey, {}, catalogs.en[knownKey])).toBe(catalogs.de[knownKey]);
  });
});

describe("tr without the middleware", () => {
  const knownKey = Object.keys(catalogs.en)[0];

  // Routers are mounted directly in several tests, and a response handler must not 500 just
  // because localeMiddleware was not on that path.
  it("reads the header itself when req.locale was never set", () => {
    const req = { get: (h: string) => (h === "X-Locale" ? "ja" : undefined) } as unknown as Request;
    expect(tr(req, knownKey, {}, catalogs.en[knownKey])).toBe(catalogs.ja[knownKey]);
  });

  it("falls back to English when there is no locale anywhere", () => {
    const req = { get: () => undefined } as unknown as Request;
    expect(tr(req, knownKey, {}, catalogs.en[knownKey])).toBe(catalogs.en[knownKey]);
  });

  it("survives a request object with no get()", () => {
    expect(tr({} as Request, knownKey, {}, "Fallback")).toBe(catalogs.en[knownKey] ?? "Fallback");
  });
});

describe("catalog integrity", () => {
  const englishKeys = Object.keys(catalogs.en).sort();
  const others = SUPPORTED_LOCALES.filter((l) => l !== DEFAULT_LOCALE);

  it.each(others)("%s has the same key set as en", (locale) => {
    expect(Object.keys(catalogs[locale]).sort()).toEqual(englishKeys);
  });

  it.each(others)("%s has no empty values", (locale) => {
    expect(englishKeys.filter((k) => !String(catalogs[locale][k]).trim())).toEqual([]);
  });

  // Losing a placeholder or a !command literal breaks interpolation or misnames a command.
  it.each(others)("%s preserves placeholders and command literals", (locale) => {
    const tokens = (s: string) => [
      ...(String(s).match(/\{\w+\}/g) || []),
      ...(String(s).match(/![a-z]+/g) || []),
    ].sort().join();

    const drift = englishKeys.filter((k) => tokens(catalogs[locale][k]) !== tokens(catalogs.en[k]));
    expect(drift).toEqual([]);
  });
});
