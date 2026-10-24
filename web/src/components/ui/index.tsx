import Link from "next/link";
import { Icon, type IconName } from "@/components/ui/icons";

export function PageHeader({ title, subtitle, back }: { title: string; subtitle?: string; back?: { href: string; label: string } }) {
  return (
    <div className="mb-6">
      {back && (
        <Link href={back.href} className="text-sm text-muted hover:text-fg">
          ← {back.label}
        </Link>
      )}
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      {subtitle && <p className="mt-1 max-w-3xl text-sm text-muted">{subtitle}</p>}
    </div>
  );
}

export function Card({ title, id, children }: { title: string; id: string; children: React.ReactNode }) {
  return (
    <section aria-labelledby={id} className="min-w-0 rounded-xl border border-border bg-surface shadow-sm">
      <h2 id={id} className="border-b border-border px-5 py-3.5 text-base font-semibold">
        {title}
      </h2>
      <div className="p-5">{children}</div>
    </section>
  );
}

const statTones = { neutral: "bg-brand/10 text-brand", ok: "bg-ok/10 text-ok", bad: "bg-danger/10 text-danger" } as const;

/** One figure of the overview: an icon chip, the label and the value. Only meaning, never colour alone. */
export function Stat({ label, value, icon, tone = "neutral", testid }: { label: string; value: number; icon: IconName; tone?: keyof typeof statTones; testid?: string }) {
  return (
    <div className="flex items-center gap-4 rounded-xl border border-border bg-surface p-4 shadow-sm">
      <span className={`flex size-11 shrink-0 items-center justify-center rounded-lg ${statTones[tone]}`}>
        <Icon name={icon} />
      </span>
      <dl>
        <dt className="text-sm text-muted">{label}</dt>
        <dd className="font-display text-3xl font-semibold leading-tight" data-testid={testid}>
          {value}
        </dd>
      </dl>
    </div>
  );
}

export function Table({ caption, head, children, empty }: { caption: string; head: string[]; children: React.ReactNode[]; empty: string }) {
  if (children.length === 0) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="overflow-x-auto" role="group" aria-label={caption} tabIndex={0}>
      <table className="w-full text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-b border-border bg-surface-2 text-xs uppercase tracking-wide text-muted">
            {head.map((h) => (
              <th key={h} scope="col" className="px-3 py-2.5 font-medium">
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

export const Row = ({ children }: { children: React.ReactNode }) => <tr className="border-b border-border last:border-0 hover:bg-surface-2/60">{children}</tr>;
export const Cell = ({ children, mono }: { children?: React.ReactNode; mono?: boolean }) => <td className={`px-3 py-2.5 align-top ${mono ? "font-mono text-xs" : ""}`}>{children}</td>;

const tones = { ok: "bg-ok/10 text-ok border-ok/40", bad: "bg-danger/10 text-danger border-danger/40", neutral: "bg-surface-2 text-muted border-border" } as const;

/** Status is never colour alone: the text says it too. */
export function Badge({ tone = "neutral", children }: { tone?: keyof typeof tones; children: React.ReactNode }) {
  return <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>;
}

export function Notice({ children }: { children: React.ReactNode }) {
  return (
    <p role="status" className="rounded-md border border-border bg-surface px-4 py-3 text-sm text-muted">
      {children}
    </p>
  );
}

/** A unified diff, one coloured line per row. Plain text, never HTML. */
export function UnifiedDiff({ text }: { text: string }) {
  return (
    <pre className="max-h-96 overflow-auto rounded-md border border-border bg-bg p-3 font-mono text-xs leading-relaxed">
      {text.split("\n").map((l, i) => (
        <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "text-ok" : l.startsWith("-") && !l.startsWith("---") ? "text-danger" : "text-muted"}>
          {l || " "}
        </div>
      ))}
    </pre>
  );
}
