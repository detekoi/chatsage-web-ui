/**
 * Server-side message localization.
 *
 * The dashboard renders `data.message` from API responses verbatim, so a response built here in
 * English shows up as an English toast in an otherwise translated UI. Routers call `req.t(...)`
 * with a catalog key and the English text; the English text is always the fallback, so an
 * untranslated key or an unknown locale degrades to exactly the previous behaviour.
 *
 * Locale comes from the `X-Locale` header the client sets from its own active language, rather
 * than from `Accept-Language` — the user's chosen UI language and their browser's preference are
 * not the same thing, and the toast has to match what is on screen.
 */

import { Request, Response, NextFunction } from "express";
import { catalogs, SUPPORTED_LOCALES, DEFAULT_LOCALE, SupportedLocale } from "./catalog";

export { SUPPORTED_LOCALES, DEFAULT_LOCALE };
export type { SupportedLocale };

/** Interpolates {name} placeholders; an absent value leaves the placeholder rather than "undefined". */
function interpolate(template: string, params: Record<string, unknown>): string {
  return template.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(params, name) && params[name] != null
      ? String(params[name])
      : match
  );
}

/**
 * Looks up a localized message.
 * @param key Dotted catalog key.
 * @param params Interpolation values.
 * @param fallback English text, used whenever the key or locale is not catalogued.
 * @param locale Target locale.
 */
export function translate(
  key: string,
  params: Record<string, unknown>,
  fallback: string,
  locale: string
): string {
  const catalog = catalogs[locale as SupportedLocale];
  const template = catalog && catalog[key];
  return interpolate(typeof template === "string" ? template : fallback, params);
}

/** Normalizes a raw header value to a supported locale, or the default. */
export function resolveLocale(raw: unknown): SupportedLocale {
  if (typeof raw !== "string") return DEFAULT_LOCALE;
  // Accept a region subtag ("pt-BR") and match on the base language.
  const base = raw.trim().toLowerCase().split(/[-_]/)[0];
  return (SUPPORTED_LOCALES as readonly string[]).includes(base)
    ? (base as SupportedLocale)
    : DEFAULT_LOCALE;
}

declare module "express-serve-static-core" {
  interface Request {
    locale?: SupportedLocale;
  }
}

/**
 * Localizes a message for a request.
 *
 * Reads the locale the middleware resolved, and falls back to reading the header itself when the
 * middleware did not run — a response handler should never 500 because a middleware was not
 * mounted on the path it happens to be reached through.
 *
 * @param req The request the response is being built for.
 * @param key Dotted catalog key.
 * @param params Interpolation values.
 * @param fallback English text, used whenever the key or locale is not catalogued.
 */
export function tr(
  req: Pick<Request, "get"> & { locale?: SupportedLocale },
  key: string,
  params: Record<string, unknown>,
  fallback: string
): string {
  const locale =
    req?.locale ?? resolveLocale(typeof req?.get === "function" ? req.get("X-Locale") : undefined);
  return translate(key, params, fallback, locale);
}

/** Resolves the request locale once so handlers do not each re-read the header. */
export function localeMiddleware(req: Request, _res: Response, next: NextFunction): void {
  req.locale = resolveLocale(req.get("X-Locale"));
  next();
}
