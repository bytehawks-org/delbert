import "server-only";
import { NextResponse, type NextRequest } from "next/server";

/**
 * Public base URL of this UI. Behind a reverse proxy (or in a container listening on 0.0.0.0) the
 * request URL is not what the browser used: take `WEB_PUBLIC_URL` if set, else the Host header.
 */
function base(request: NextRequest): URL {
  if (process.env.WEB_PUBLIC_URL) return new URL(process.env.WEB_PUBLIC_URL);
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? request.nextUrl.host;
  const proto = request.headers.get("x-forwarded-proto") ?? request.nextUrl.protocol.replace(":", "");
  return new URL(`${proto}://${host}`);
}

export function publicUrl(path: string, request: NextRequest): URL {
  return new URL(path, base(request));
}

/**
 * State-changing requests must come from this site: the cookie is `SameSite=Strict`, and the
 * browser also sends `Origin` on same-site POSTs, which has to match.
 */
export function sameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).host === base(request).host;
  } catch {
    return false;
  }
}

export function forbidden() {
  return NextResponse.json({ error: "forbidden" }, { status: 403 });
}
