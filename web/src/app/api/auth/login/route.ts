import { NextResponse, type NextRequest } from "next/server";
import { core } from "@/lib/core";
import { forbidden, sameOrigin } from "@/lib/http";
import { COOKIE, cookieOptions, seal } from "@/lib/session";

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) return forbidden();
  const body = (await request.json().catch(() => null)) as { username?: unknown; password?: unknown } | null;
  if (typeof body?.username !== "string" || typeof body.password !== "string") {
    return NextResponse.json({ error: "generic" }, { status: 400 });
  }
  let result;
  try {
    result = await core().POST("/v1/auth/login", { body: { username: body.username, password: body.password } });
  } catch {
    return NextResponse.json({ error: "unavailable" }, { status: 502 });
  }
  const { data, response } = result;
  if (response.status === 429) return NextResponse.json({ error: "throttled" }, { status: 429 });
  if (!data) return NextResponse.json({ error: response.status === 401 ? "invalid" : "generic" }, { status: response.status === 401 ? 401 : 502 });

  const res = NextResponse.json({ mfaRequired: data.mfa_required });
  res.cookies.set(COOKIE, await seal({ token: data.token, mfaPending: data.mfa_required }), cookieOptions(data.mfa_required));
  return res;
}
