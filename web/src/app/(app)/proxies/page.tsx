import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { Badge, Cell, Notice, PageHeader, Row, Table } from "@/components/ui";
import { core } from "@/lib/core";
import { stamp, unwrap } from "@/lib/data";
import { ProxyAdmin } from "@/components/proxy-admin";
import { requireMe } from "@/lib/me";
import { canGlobal } from "@/lib/perm";

export async function generateMetadata(): Promise<Metadata> {
  return { title: (await getTranslations("proxies"))("title") };
}

export default async function Proxies() {
  const { me, token } = await requireMe();
  const t = await getTranslations("proxies");
  const proxies = unwrap(await core(token).GET("/v1/proxies"));
  return (
    <>
      <PageHeader title={t("title")} subtitle={t("subtitle")} />
      {proxies && canGlobal(me, "proxies:write") && <ProxyAdmin names={proxies.map((x) => x.name)} />}
      {proxies ? (
        <Table caption={t("title")} head={[t("name"), t("state"), t("dns"), t("agents"), t("lastSeen")]} empty={t("none")}>
          {proxies.map((x) => (
            <Row key={x.name}>
              <Cell>{x.name}</Cell>
              <Cell>{x.enrolled ? <Badge tone="ok">{t("enrolled")}</Badge> : <Badge>{t("pending")}</Badge>}</Cell>
              <Cell>{x.dns_names.join(", ") || "—"}</Cell>
              <Cell>{x.agents}</Cell>
              <Cell>{stamp(x.last_seen)}</Cell>
            </Row>
          ))}
        </Table>
      ) : (
        <Notice>{t("denied")}</Notice>
      )}
    </>
  );
}
