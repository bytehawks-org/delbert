import { NextResponse, type NextRequest } from "next/server";
import { core } from "@/lib/core";
import { forbidden, publicUrl, sameOrigin } from "@/lib/http";
import { COOKIE, getSession } from "@/lib/session";

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) return forbidden();
  const session = await getSession();
  if (session) await core(session.token).POST("/v1/auth/logout").catch(() => undefined); // best effort: the cookie goes either way
  const res = NextResponse.redirect(publicUrl("/login", request), 303);
  res.cookies.delete(COOKIE);
  return res;
}

/** Used when the Core no longer accepts the session (expired, revoked): drop the cookie and sign in again. */
export async function GET(request: NextRequest) {
  const res = NextResponse.redirect(publicUrl("/login?expired=1", request), 303);
  res.cookies.delete(COOKIE);
  return res;
}
