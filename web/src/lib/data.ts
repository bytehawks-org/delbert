import "server-only";
import { notFound } from "next/navigation";

type Result<T> = { data?: T; error?: unknown; response: Response };

/**
 * Unwraps a Core response for a read-only view. A 403 means the role does not cover this part of
 * the platform (`null`, the page shows a notice); a 404 is a 404; anything else is a real failure.
 */
export function unwrap<T>({ data, response }: Result<T>): T | null {
  if (data !== undefined) return data;
  if (response.status === 403) return null;
  if (response.status === 404) notFound();
  throw new Error(`Core answered ${response.status}`);
}

/** Epoch seconds (or microseconds) to a short local-neutral timestamp, server side, in UTC. */
export function stamp(value: number | null | undefined, unit: "s" | "us" = "s"): string {
  if (value == null) return "—";
  const ms = unit === "s" ? value * 1000 : Math.floor(value / 1000);
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19) + "Z";
}
