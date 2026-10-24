/** What the signed-in user may do, from `GET /v1/me`. Only hides controls: the Core enforces every permission. */
export interface Grants {
  permissions: string[];
  tenants: Record<string, string[]>;
}

export function can(me: Grants, permission: string, tenant: string): boolean {
  const has = (list: string[] | undefined) => !!list && (list.includes("*") || list.includes(permission));
  return has(me.permissions) || has(me.tenants[tenant]);
}

/** A permission granted globally (not through a tenant assignment). */
export function canGlobal(me: Grants, permission: string): boolean {
  return me.permissions.includes("*") || me.permissions.includes(permission) || me.permissions.includes(`${permission.split(":")[0]}:*`);
}
