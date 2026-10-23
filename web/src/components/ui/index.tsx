import Link from "next/link";

export function PageHeader({ title, subtitle, back }: { title: string; subtitle?: string; back?: { href: string; label: string } }) {
  return (
    <div className="mb-6">
      {back && (
        <Link href={back.href} className="text-sm text-muted hover:text-fg">
          ← {back.label}
        </Link>
      )}
      <h1 className="text-2xl font-semibold">{title}</h1>
      {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
    </div>
  );
}

export function Card({ title, id, children }: { title: string; id: string; children: React.ReactNode }) {
  return (
    <section aria-labelledby={id} className="rounded-lg border border-border bg-surface p-5">
      <h2 id={id} className="mb-3 text-lg font-medium">
        {title}
      </h2>
      {children}
    </section>
  );
}

export function Table({ caption, head, children, empty }: { caption: string; head: string[]; children: React.ReactNode[]; empty: string }) {
  if (children.length === 0) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-b border-border text-muted">
            {head.map((h) => (
              <th key={h} scope="col" className="py-2 pr-4 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export const Row = ({ children }: { children: React.ReactNode }) => <tr className="border-b border-border last:border-0">{children}</tr>;
export const Cell = ({ children, mono }: { children?: React.ReactNode; mono?: boolean }) => <td className={`py-2 pr-4 align-top ${mono ? "font-mono text-xs" : ""}`}>{children}</td>;

const tones = { ok: "text-ok border-ok", bad: "text-danger border-danger", neutral: "text-muted border-border" } as const;

/** Status is never colour alone: the text says it too. */
export function Badge({ tone = "neutral", children }: { tone?: keyof typeof tones; children: React.ReactNode }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${tones[tone]}`}>{children}</span>;
}

export function Notice({ children }: { children: React.ReactNode }) {
  return (
    <p role="status" className="rounded-md border border-border bg-surface px-4 py-3 text-sm text-muted">
      {children}
    </p>
  );
}
