import "server-only";
import { EncryptJWT, jwtDecrypt } from "jose";
import { cookies } from "next/headers";

/**
 * The browser never sees the Core's session token. It holds an encrypted, HttpOnly cookie that only
 * this server can open; the token inside is sent to the Core from the server (backend-for-frontend).
 */
export const COOKIE = "delbert_web";
const FULL_MAX_AGE = 8 * 3600; // as long as a Core session
const PENDING_MAX_AGE = 5 * 60; // time to give the second factor

export interface Session {
  /** The Core's bearer token. */
  token: string;
  /** The password was accepted but the second factor is still missing. */
  mfaPending: boolean;
}

function key(): Uint8Array {
  const configured = process.env.WEB_SESSION_SECRET;
  if (configured) {
    const raw = Buffer.from(configured, "base64url");
    if (raw.length !== 32) throw new Error("WEB_SESSION_SECRET must be 32 bytes, base64url encoded (openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')");
    return raw;
  }
  if (process.env.NODE_ENV === "production") throw new Error("WEB_SESSION_SECRET is required in production");
  return new TextEncoder().encode("development-only-session-key-32b!");
}

export async function seal(session: Session): Promise<string> {
  const maxAge = session.mfaPending ? PENDING_MAX_AGE : FULL_MAX_AGE;
  return new EncryptJWT({ t: session.token, p: session.mfaPending })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(`${maxAge}s`)
    .encrypt(key());
}

export async function open(value: string): Promise<Session | null> {
  try {
    const { payload } = await jwtDecrypt(value, key());
    if (typeof payload.t !== "string") return null;
    return { token: payload.t, mfaPending: payload.p === true };
  } catch {
    return null;
  }
}

export async function getSession(): Promise<Session | null> {
  const value = (await cookies()).get(COOKIE)?.value;
  return value ? open(value) : null;
}

/** Cookie attributes. `Secure` can only be switched off for plain-HTTP development. */
export function cookieOptions(pending: boolean) {
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    secure: process.env.WEB_INSECURE_COOKIES !== "true",
    path: "/",
    maxAge: pending ? PENDING_MAX_AGE : FULL_MAX_AGE,
  };
}
