import type { Metadata } from "next";
import Link from "next/link";
import { getTranslations } from "next-intl/server";
import { ArtifactUpload } from "@/components/artifact-upload";
import { EnrollmentKeys } from "@/components/enrollment-keys";
import { SecretsPanel } from "@/components/secrets-panel";
import { AgentAdmin } from "@/components/agent-admin";
import { TenantAccess } from "@/components/tenant-access";
import { TenantArchive } from "@/components/tenant-archive";
import { AgentsTable } from "@/components/agents-table";
import { Badge, Card, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { can, canGlobal } from "@/lib/perm";

type Props = { params: Promise<{ tenant: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).tenant) };
}

export default async function Tenant({ params }: Props) {
  const tenant = decodeURIComponent((await params).tenant);
  const { me, token } = await requireMe();
  const t = await getTranslations("tenants");
  const tAccess = await getTranslations("access");
  const tAgents = await getTranslations("agentAdmin");
  const api = core(token);
  const p = { params: { path: { tenant } } };
  const [agents, policies, artifacts, secrets, keys, assignments, settings, roles] = await Promise.all([
    api.GET("/v1/tenants/{tenant}/agents", p),
    api.GET("/v1/tenants/{tenant}/policies", p),
    api.GET("/v1/tenants/{tenant}/artifacts", p),
    api.GET("/v1/tenants/{tenant}/secrets", p),
    api.GET("/v1/tenants/{tenant}/enrollment-keys", p),
    api.GET("/v1/tenants/{tenant}/assignments", p),
    api.GET("/v1/tenants/{tenant}/settings", p),
    api.GET("/v1/roles"),
  ]);
  const [a, pol, art, sec, ek] = [unwrap(agents), unwrap(policies), unwrap(artifacts), unwrap(secrets), unwrap(keys)];
  const [asg, cfg, rl] = [unwrap(assignments), unwrap(settings), unwrap(roles)];
  const now = Math.floor(Date.now() / 1000);
  const denied = <Notice>{t("denied")}</Notice>;

  return (
    <div className="space-y-6">
      <PageHeader title={tenant} back={{ href: "/tenants", label: t("title") }} />
      <Card id="agents" title={t("agents")}>
        {a ? <AgentsTable agents={a.map((x) => ({ ...x, tenant }))} /> : denied}
        {a && can(me, "agents:write", tenant) && (
          <details className="mt-4">
            <summary className="cursor-pointer text-sm font-medium text-accent">{tAgents("manage")}</summary>
            <div className="mt-3">
              <AgentAdmin tenant={tenant} agents={a.map((x) => ({ name: x.name, groups: x.groups }))} />
            </div>
          </details>
        )}
      </Card>
      {ek && (
        <Card id="keys" title={t("keys")}>
          <EnrollmentKeys tenant={tenant} canWrite={can(me, "agents:enroll", tenant)} keys={ek.map((k) => ({ ...k, expired: k.expires_at < now, expiresLabel: stamp(k.expires_at) }))} />
        </Card>
      )}
      <Card id="policies" title={t("policies")}>
        {can(me, "policies:write", tenant) && (
          <Link href={`/tenants/${encodeURIComponent(tenant)}/policies/new`} className="mb-3 inline-block rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg">
            {t("newPolicy")}
          </Link>
        )}
        {pol ? (
          <Table caption={t("policies")} head={[t("name"), t("activeVersion"), t("latestVersion")]} empty={t("noPolicies")}>
            {pol.map((x) => (
              <Row key={x.name}>
                <Cell>
                  <Link href={`/tenants/${encodeURIComponent(tenant)}/policies/${encodeURIComponent(x.name)}`} className="font-medium text-accent hover:underline">
                    {x.name}
                  </Link>
                </Cell>
                <Cell>{x.active_version ?? <Badge>{t("inactive")}</Badge>}</Cell>
                <Cell>{x.latest_version ?? "—"}</Cell>
              </Row>
            ))}
          </Table>
        ) : (
          denied
        )}
      </Card>
      {asg && (
        <Card id="access" title={tAccess("title")}>
          <TenantAccess
            tenant={tenant}
            assignments={asg}
            roles={(rl ?? []).filter((r) => r.scope !== "global").map((r) => r.name)}
            approvalRequired={cfg ? cfg.approval_required : null}
            canAssign={can(me, "roles:assign", tenant)}
            canSettings={can(me, "tenants:settings", tenant)}
          />
        </Card>
      )}
      <div className="grid gap-6 md:grid-cols-2">
        <Card id="artifacts" title={t("artifacts")}>
          {art ? (
            <>
              {can(me, "artifacts:write", tenant) && <ArtifactUpload tenant={tenant} />}
              <Table caption={t("artifacts")} head={[t("name"), t("version"), t("size"), "SHA-256"]} empty={t("noArtifacts")}>
                {art.map((x) => (
                  <Row key={x.name}>
                    <Cell>{x.name}</Cell>
                    <Cell>{x.version}</Cell>
                    <Cell>{x.size}</Cell>
                    <Cell mono>{x.sha256.slice(0, 12)}…</Cell>
                  </Row>
                ))}
              </Table>
            </>
          ) : (
            denied
          )}
        </Card>
        <Card id="secrets" title={t("secrets")}>
          {sec ? <SecretsPanel tenant={tenant} canWrite={can(me, "secrets:write", tenant)} secrets={sec.map((x) => ({ name: x.name, updated_by: x.updated_by, updatedLabel: stamp(x.updated_at) }))} /> : denied}
        </Card>
      </div>
      {canGlobal(me, "tenants:delete") && (
        <Card id="danger" title={t("dangerZone")}>
          <TenantArchive tenant={tenant} />
        </Card>
      )}
    </div>
  );
}
