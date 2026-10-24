import { NextResponse, type NextRequest } from "next/server";

// Runs before every page: a fresh CSP nonce, the security headers, and the first gate for pages that
// need a session. The gate only checks that a session cookie exists; the pages verify and decrypt it
// (the UI is never the security boundary: the Core enforces every permission).

const COOKIE = "delbert_web";
const PUBLIC = [/^\/login$/, /^\/api\/auth\//, /^\/auth\/callback$/, /^\/api\/locale$/];

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const dev = process.env.NODE_ENV !== "production";
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'${dev ? " 'unsafe-inline'" : ""}`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");

  const path = request.nextUrl.pathname;
  if (!PUBLIC.some((re) => re.test(path)) && !request.cookies.has(COOKIE)) {
    // Programmatic callers (the pass-through, the live stream) get a status, not a login page.
    if (path.startsWith("/api/")) return new NextResponse(JSON.stringify({ error: "not signed in" }), { status: 401, headers: { "content-type": "application/json", "Cache-Control": "no-store" } });
    const to = request.nextUrl.clone();
    to.pathname = "/login";
    to.search = "";
    return NextResponse.redirect(to);
  }

  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "same-origin");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.headers.set("Cache-Control", "no-store");
  if ((request.headers.get("x-forwarded-proto") ?? request.nextUrl.protocol.replace(":", "")) === "https") {
    response.headers.set("Strict-Transport-Security", "max-age=31536000");
  }
  return response;
}

export const config = {
  matcher: [{ source: "/((?!_next/static|_next/image|favicon.ico).*)" }],
};
