import { NextResponse, type NextRequest } from "next/server";
import { core } from "@/lib/core";
import { publicUrl } from "@/lib/http";
import { COOKIE, cookieOptions, seal } from "@/lib/session";

/**
 * Where the Core sends the browser after single sign-on (`DELBERT_UI_URL`): `?code=` is a one-time
 * code that is exchanged here, on the server, for a session; `?sso_error=` is a refusal.
 */
export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const refused = request.nextUrl.searchParams.get("sso_error");
  const back = (query: string) => NextResponse.redirect(publicUrl(`/login?${query}`, request), 303);
  if (refused) return back(`sso_error=${encodeURIComponent(refused.slice(0, 200))}`);
  if (!code) return back("expired=1");

  const { data } = await core().POST("/v1/auth/sso/exchange", { body: { code } }).catch(() => ({ data: undefined }));
  if (!data) return back("expired=1");
  const res = NextResponse.redirect(publicUrl("/", request), 303);
  res.cookies.set(COOKIE, await seal({ token: data.token, mfaPending: false }), cookieOptions(false));
  return res;
}
