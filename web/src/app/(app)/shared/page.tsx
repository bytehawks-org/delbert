import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { ArtifactUpload } from "@/components/artifact-upload";
import { VariablesPanel } from "@/components/variables-panel";
import { Card, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { unwrap } from "@/lib/data";
import { requireMe } from "@/lib/me";
import { canGlobal } from "@/lib/perm";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("shared"))("title") };
}

/** Platform-wide content every tenant inherits: artifacts and variables (constants included). */
export default async function Shared() {
  const { me, token } = await requireMe();
  const t = await getTranslations("shared");
  const tTenants = await getTranslations("tenants");
  const api = core(token);
  const [artifacts, variables] = [unwrap(await api.GET("/v1/globals/artifacts")), unwrap(await api.GET("/v1/globals/variables"))];
  if (!artifacts || !variables) return <Notice>{t("denied")}</Notice>;
  const canWrite = canGlobal(me, "globals:write");
  return (
    <div className="space-y-6">
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      <Card id="shared-artifacts" title={t("artifacts")}>
        <p className="mb-3 text-xs text-muted">{t("artifactsNote")}</p>
        {canWrite && <ArtifactUpload />}
        <Table caption={t("artifacts")} head={[tTenants("name"), tTenants("version"), tTenants("size"), "SHA-256"]} empty={t("noArtifacts")}>
          {artifacts.map((x) => (
            <Row key={x.name}>
              <Cell>{x.name}</Cell>
              <Cell>{x.version}</Cell>
              <Cell>{x.size}</Cell>
              <Cell mono>{x.sha256.slice(0, 12)}…</Cell>
            </Row>
          ))}
        </Table>
      </Card>
      <Card id="shared-variables" title={t("variables")}>
        <VariablesPanel variables={variables} canWrite={canWrite} />
      </Card>
    </div>
  );
}
