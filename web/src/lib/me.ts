import "server-only";
import { cache } from "react";
import { redirect } from "next/navigation";
import { core } from "./core";
import { getSession } from "./session";

/** The signed-in user (one Core call per request). Sends the browser to the login page when there is no valid session. */
export const requireMe = cache(async () => {
  const session = await getSession();
  if (!session || session.mfaPending) redirect("/api/auth/logout"); // GET: drops the cookie, then /login
  const { data, response } = await core(session.token).GET("/v1/me").catch(() => ({ data: undefined, response: undefined }));
  if (!data) redirect(response?.status === 401 || !response ? "/api/auth/logout" : "/login");
  return { me: data, token: session.token };
});
