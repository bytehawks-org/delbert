import { NextResponse, type NextRequest } from "next/server";
import { CORE_PUBLIC_URL } from "@/lib/core";

/** Start single sign-on: the browser goes to the Core, which sends it on to the identity provider. */
export async function GET(_request: NextRequest, { params }: { params: Promise<{ provider: string }> }) {
  const { provider } = await params;
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(provider)) return NextResponse.json({ error: "generic" }, { status: 400 });
  return NextResponse.redirect(`${CORE_PUBLIC_URL.replace(/\/$/, "")}/v1/auth/sso/${provider}/login`, 303);
}
