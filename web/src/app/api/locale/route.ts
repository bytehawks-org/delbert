import { NextResponse, type NextRequest } from "next/server";
import { forbidden, sameOrigin } from "@/lib/http";
import { LOCALES, LOCALE_COOKIE } from "@/i18n/request";

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) return forbidden();
  const body = (await request.json().catch(() => null)) as { locale?: unknown } | null;
  if (typeof body?.locale !== "string" || !(body.locale in LOCALES)) return NextResponse.json({ error: "generic" }, { status: 400 });
  const res = new NextResponse(null, { status: 204 });
  res.cookies.set(LOCALE_COOKIE, body.locale, { path: "/", sameSite: "lax", maxAge: 365 * 24 * 3600 });
  return res;
}
