import { type NextRequest } from "next/server";
import { CORE_URL } from "@/lib/core";
import { getSession } from "@/lib/session";

/**
 * Live status for the browser: the Core's Server-Sent Events stream (`GET /v1/stream`) passed
 * through with the session added server side. The stream only says "something changed"; the
 * pages refetch. It ends when the browser leaves (the request signal is passed on) or the Core
 * closes it, and the browser's EventSource reconnects by itself.
 */
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const session = await getSession();
  if (!session || session.mfaPending) return new Response(null, { status: 401 });
  const upstream = await fetch(`${CORE_URL}/v1/stream`, {
    headers: { authorization: `Bearer ${session.token}`, accept: "text/event-stream" },
    cache: "no-store",
    signal: request.signal,
  }).catch(() => null);
  if (!upstream?.body) return new Response(null, { status: 502 });
  if (!upstream.ok) return new Response(null, { status: upstream.status === 401 ? 401 : 502 });
  return new Response(upstream.body, {
    headers: { "content-type": "text/event-stream", "cache-control": "no-store, no-transform", "x-accel-buffering": "no" },
  });
}
