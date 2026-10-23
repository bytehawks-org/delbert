import "server-only";
import createClient from "openapi-fetch";
import type { paths } from "./api/schema";

/** Where this server reaches the Core (inside the cluster or network). */
export const CORE_URL = process.env.DELBERT_CORE_URL ?? "http://localhost:8080";

/** Where the *browser* reaches the Core, for the single sign-on redirects. */
export const CORE_PUBLIC_URL = process.env.WEB_CORE_PUBLIC_URL ?? CORE_URL;

/**
 * Typed client generated from the Core's OpenAPI document (`npm run gen:api`). The Core's own
 * certificate authority must be trusted by Node (`NODE_EXTRA_CA_CERTS`).
 */
export function core(token?: string) {
  return createClient<paths>({
    baseUrl: CORE_URL,
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    cache: "no-store",
  });
}

/** The Core's `{"error": "..."}` body, if that is what an error looks like. */
export function errorText(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "error" in error && typeof (error as { error: unknown }).error === "string"
    ? (error as { error: string }).error
    : undefined;
}
