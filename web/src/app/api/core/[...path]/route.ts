import { NextResponse, type NextRequest } from "next/server";
import { CORE_URL } from "@/lib/core";
import { forbidden, sameOrigin } from "@/lib/http";
import { getSession } from "@/lib/session";

/**
 * The browser's only way to change anything: a narrow pass-through to the Core with the session
 * attached on the server. Only the calls the UI makes are allowed (everything else is a 404 here,
 * whatever the user may do against the Core), and the request must come from this site.
 */
const SEG = "[A-Za-z0-9._~%-]+";
const T = `/v1/tenants/${SEG}`;
const ALLOWED: Record<string, RegExp[]> = {
  POST: [
    new RegExp(`^${T}/policies(/validate)?$`),
    new RegExp(`^${T}/policies/${SEG}/versions/\\d+/(submit|approve|reject|activate|rollback)$`),
    new RegExp(`^${T}/enrollment-keys$`),
    new RegExp(`^/v1/(users|roles|sso/providers|tenants|proxies)$`),
    new RegExp(`^${T}/agents$`),
    new RegExp(`^/v1/me/(mfa/(enroll|confirm|disable)|tokens)$`),
    new RegExp(`^/v1/sso/providers/${SEG}/test$`),
    new RegExp(`^/v1/content/sources(/${SEG}/sync)?$`),
  ],
  PUT: [new RegExp(`^${T}/(settings|assignments/${SEG})$`), new RegExp(`^${T}/secrets/${SEG}$`), new RegExp(`^${T}/artifacts/${SEG}$`), new RegExp(`^/v1/(users|roles|sso/providers|content/sources)/${SEG}$`), new RegExp(`^${T}/agents/${SEG}$`)],
  DELETE: [
    new RegExp(`^${T}/enrollment-keys/${SEG}$`),
    new RegExp(`^${T}/secrets/${SEG}$`),
    new RegExp(`^/v1/(users|roles|sso/providers|content/sources|tenants|proxies)/${SEG}$`),
    new RegExp(`^${T}/agents/${SEG}$`),
    new RegExp(`^/v1/users/${SEG}/(mfa|sessions)$`),
    new RegExp(`^/v1/me/(tokens|sessions)/${SEG}$`),
  ],
};

async function forward(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  if (!sameOrigin(request)) return forbidden();
  const path = "/" + (await params).path.join("/");
  if (!ALLOWED[request.method]?.some((re) => re.test(path))) return NextResponse.json({ error: "not available through the UI" }, { status: 404 });
  const session = await getSession();
  if (!session || session.mfaPending) return NextResponse.json({ error: "not signed in" }, { status: 401 });

  const body = request.method === "DELETE" ? undefined : await request.arrayBuffer();
  const res = await fetch(`${CORE_URL}${path}`, {
    method: request.method,
    headers: { authorization: `Bearer ${session.token}`, ...(request.headers.get("content-type") ? { "content-type": request.headers.get("content-type")! } : {}) },
    body,
    cache: "no-store",
  }).catch(() => null);
  if (!res) return NextResponse.json({ error: "the Core is not reachable" }, { status: 502 });
  return new NextResponse(res.status === 204 ? null : await res.arrayBuffer(), { status: res.status, headers: { "content-type": res.headers.get("content-type") ?? "application/json" } });
}

export { forward as POST, forward as PUT, forward as DELETE };
