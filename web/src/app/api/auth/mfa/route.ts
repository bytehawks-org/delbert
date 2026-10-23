import { NextResponse, type NextRequest } from "next/server";
import { core } from "@/lib/core";
import { forbidden, sameOrigin } from "@/lib/http";
import { COOKIE, cookieOptions, getSession, seal } from "@/lib/session";

export async function POST(request: NextRequest) {
  if (!sameOrigin(request)) return forbidden();
  const session = await getSession();
  if (!session?.mfaPending) return NextResponse.json({ error: "expired" }, { status: 401 });
  const body = (await request.json().catch(() => null)) as { code?: unknown } | null;
  if (typeof body?.code !== "string") return NextResponse.json({ error: "generic" }, { status: 400 });

  let result;
  try {
    result = await core(session.token).POST("/v1/auth/mfa", { body: { code: body.code } });
  } catch {
    return NextResponse.json({ error: "unavailable" }, { status: 502 });
  }
  const { response } = result;
  if (response.status === 429) return NextResponse.json({ error: "throttled" }, { status: 429 });
  if (!response.ok) return NextResponse.json({ error: response.status === 401 ? "invalidCode" : "generic" }, { status: response.status === 401 ? 401 : 502 });

  // The Core's session is the same; only the cookie's lifetime changes from "pending" to "full".
  const res = NextResponse.json({ ok: true });
  res.cookies.set(COOKIE, await seal({ token: session.token, mfaPending: false }), cookieOptions(false));
  return res;
}
