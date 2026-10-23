import { cookies, headers } from "next/headers";
import { getRequestConfig } from "next-intl/server";

/** Supported languages; add a catalog in `messages/` and a name here to extend. */
export const LOCALES = { en: "English", it: "Italiano" } as const;
export type Locale = keyof typeof LOCALES;
export const LOCALE_COOKIE = "NEXT_LOCALE";

function isLocale(v: string | undefined): v is Locale {
  return v !== undefined && v in LOCALES;
}

/** The cookie (set by the language switcher), then the browser's preference, then English. */
async function detect(): Promise<Locale> {
  const fromCookie = (await cookies()).get(LOCALE_COOKIE)?.value;
  if (isLocale(fromCookie)) return fromCookie;
  const accept = (await headers()).get("accept-language") ?? "";
  for (const part of accept.split(",")) {
    const tag = part.split(";")[0]?.trim().toLowerCase().split("-")[0];
    if (isLocale(tag)) return tag;
  }
  return "en";
}

export default getRequestConfig(async () => {
  const locale = await detect();
  return { locale, messages: (await import(`../../messages/${locale}.json`)).default };
});
