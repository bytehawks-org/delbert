"use client";

import loader from "@monaco-editor/loader";
import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { callCore } from "@/lib/mutate";

// Monaco comes from this site (scripts/copy-monaco.mjs), never from a CDN.
loader.config({ paths: { vs: "/monaco/vs" } });

/**
 * The CSP only lets `<style>` elements with the page's nonce apply. Monaco creates its own at run
 * time, so give them the nonce instead of opening `style-src` to every inline style.
 */
function nonceMonacoStyles() {
  const nonce = document.querySelector<HTMLScriptElement>("script[nonce]")?.nonce;
  const marker = "__delbertStyleNonce";
  if (!nonce || (document as unknown as Record<string, unknown>)[marker]) return;
  (document as unknown as Record<string, unknown>)[marker] = true;
  const create = document.createElement.bind(document);
  document.createElement = ((tag: string, options?: ElementCreationOptions) => {
    const element = create(tag, options);
    if (tag.toLowerCase() === "style") element.setAttribute("nonce", nonce);
    return element;
  }) as typeof document.createElement;
}
const Monaco = dynamic(() => import("@monaco-editor/react").then((m) => m.default), { ssr: false, loading: () => <p className="p-4 text-sm text-muted">…</p> });

type Entry = { path: string; size: number };
type Loaded = { content: string; binary: boolean };
type Check = { state: "idle" | "checking" } | { state: "ok" } | { state: "bad"; errors: string[] };

const button = "rounded-md border border-border px-2 py-1 text-xs hover:bg-surface disabled:opacity-50";

function languageOf(path: string): string {
  const name = path.replace(/\.(j2|jinja2?)$/, "");
  const ext = name.split(".").pop()?.toLowerCase() ?? "";
  return ({ yaml: "yaml", yml: "yaml", json: "json", md: "markdown", ini: "ini", conf: "ini", toml: "ini", sh: "shell", py: "python", xml: "xml", html: "html", js: "javascript" } as Record<string, string>)[ext] ?? "plaintext";
}

type Node = { name: string; path: string; children: Map<string, Node>; file: boolean };

function tree(paths: string[]): Node {
  const root: Node = { name: "", path: "", children: new Map(), file: false };
  for (const p of paths) {
    let node = root;
    const parts = p.split("/");
    parts.forEach((part, i) => {
      const path = parts.slice(0, i + 1).join("/");
      if (!node.children.has(part)) node.children.set(part, { name: part, path, children: new Map(), file: i === parts.length - 1 });
      node = node.children.get(part)!;
    });
  }
  return root;
}

/**
 * Edits a repository that a content source reads: the layout of docs/REPOSITORY.md. Nothing is
 * written until "commit": the changes are kept here, validated by the Core as the repository they
 * would make (the same parser as the sync), and committed to a new branch for review.
 */
export function RepoEditor({ source, kind, tenant, files: initial, revision, writable, canEdit }: { source: string; kind: string; tenant: string | null; files: Entry[]; revision: string; writable: boolean; canEdit: boolean }) {
  const t = useTranslations("repo");
  const router = useRouter();
  const editable = writable && canEdit;
  const base = `/v1/content/sources/${encodeURIComponent(source)}`;

  const [files, setFiles] = useState(initial);
  const [loaded, setLoaded] = useState<Record<string, Loaded>>({});
  const [edits, setEdits] = useState<Record<string, string | null>>({}); // null = deleted
  const [current, setCurrent] = useState<string | null>(null);
  const [check, setCheck] = useState<Check>({ state: "idle" });
  const [message, setMessage] = useState("");
  const [newPath, setNewPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ branch: string | null; files: number } | null>(null);
  const [dark, setDark] = useState(false);
  const live = useRef(0);
  useEffect(() => nonceMonacoStyles(), []);

  useEffect(() => {
    const root = document.documentElement;
    const update = () => setDark(root.classList.contains("dark"));
    update();
    const observer = new MutationObserver(update);
    observer.observe(root, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);

  const all = useMemo(() => {
    const set = new Set(files.map((f) => f.path));
    for (const [p, v] of Object.entries(edits)) v === null ? set.delete(p) : set.add(p);
    return [...set].sort();
  }, [files, edits]);
  const root = useMemo(() => tree(all), [all]);
  const dirty = Object.keys(edits);

  const open = useCallback(
    async (path: string) => {
      setCurrent(path);
      if (path in loaded || (path in edits && edits[path] !== null && !files.some((f) => f.path === path))) return;
      const res = await fetch(`/api/core${base}/file?path=${encodeURIComponent(path)}`).catch(() => null);
      if (!res?.ok) return setError(t("cannotRead", { path }));
      const body = (await res.json()) as { encoding: string; content: string };
      setLoaded((l) => ({ ...l, [path]: { content: body.encoding === "utf8" ? body.content : "", binary: body.encoding !== "utf8" } }));
    },
    [base, files, edits, loaded, t],
  );

  // Every pause asks the Core what the repository would look like after the change.
  useEffect(() => {
    if (dirty.length === 0) return setCheck({ state: "idle" });
    setCheck({ state: "checking" });
    const mine = ++live.current;
    const handle = setTimeout(async () => {
      const changes = dirty.map((p) => (edits[p] === null ? { path: p, delete: true } : { path: p, content: edits[p] }));
      const r = await callCore<{ ok: boolean; errors: string[] }>("POST", `${base}/validate`, { changes });
      if (mine !== live.current) return;
      setCheck(r.ok && r.data ? (r.data.ok ? { state: "ok" } : { state: "bad", errors: r.data.errors }) : { state: "bad", errors: [r.error ?? "?"] });
    }, 600);
    return () => clearTimeout(handle);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(edits), base]);

  const value = current === null ? "" : current in edits ? (edits[current] ?? "") : (loaded[current]?.content ?? "");
  const binary = current !== null && loaded[current]?.binary === true;

  function change(path: string, text: string) {
    const original = loaded[path]?.content;
    setEdits((e) => {
      const next = { ...e };
      if (original !== undefined && original === text && files.some((f) => f.path === path)) delete next[path];
      else next[path] = text;
      return next;
    });
  }

  function addFile() {
    const path = newPath.trim().replace(/^\/+/, "");
    if (!path || all.includes(path)) return;
    setEdits((e) => ({ ...e, [path]: "" }));
    setLoaded((l) => ({ ...l, [path]: { content: "", binary: false } }));
    setNewPath("");
    setCurrent(path);
  }

  function remove(path: string) {
    if (files.some((f) => f.path === path)) setEdits((e) => ({ ...e, [path]: null }));
    else setEdits((e) => Object.fromEntries(Object.entries(e).filter(([p]) => p !== path)));
    if (current === path) setCurrent(null);
  }

  function revert(path: string) {
    setEdits((e) => Object.fromEntries(Object.entries(e).filter(([p]) => p !== path)));
  }

  async function commit() {
    setBusy(true);
    setError(null);
    const changes = dirty.map((p) => (edits[p] === null ? { path: p, delete: true } : { path: p, content: edits[p] }));
    const r = await callCore<{ branch: string | null; files: number }>("POST", `${base}/commits`, { message, changes });
    setBusy(false);
    if (!r.ok || !r.data) return setError(r.error ?? "?");
    setDone({ branch: r.data.branch, files: r.data.files });
    // The repository moved on (a directory) or a branch exists (git): start again from the Core's view.
    setEdits({});
    setLoaded({});
    setMessage("");
    setFiles(all.map((p) => ({ path: p, size: 0 })));
    router.refresh();
  }

  const render = (node: Node, depth = 0): React.ReactNode =>
    [...node.children.values()]
      .sort((a, b) => Number(a.file) - Number(b.file) || a.name.localeCompare(b.name))
      .map((n) =>
        n.file ? (
          <li key={n.path}>
            <button
              type="button"
              onClick={() => open(n.path)}
              aria-current={current === n.path ? "true" : undefined}
              className={`flex w-full items-center gap-1 rounded px-1 py-0.5 text-left text-sm hover:bg-surface ${current === n.path ? "bg-surface font-medium" : ""}`}
              style={{ paddingLeft: `${depth * 12 + 4}px` }}
            >
              <span className="truncate font-mono">{n.name}</span>
              {n.path in edits && <span className="text-xs text-accent" aria-label={edits[n.path] === null ? t("deleted") : t("modified")}>{edits[n.path] === null ? "−" : "●"}</span>}
            </button>
          </li>
        ) : (
          <li key={n.path}>
            <details open={depth < 2}>
              <summary className="cursor-pointer select-none rounded px-1 py-0.5 text-sm text-muted hover:bg-surface" style={{ paddingLeft: `${depth * 12}px` }}>
                {n.name}
              </summary>
              <ul>{render(n, depth + 1)}</ul>
            </details>
          </li>
        ),
      );

  const hint = editable ? null : writable ? t("noPermission") : t("readOnly");

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">
        {tenant ? t("ofTenant", { tenant }) : t("platform")} · <span className="font-mono">{revision.slice(0, 12)}</span> · {kind}
      </p>
      {hint && <p className="rounded-md border border-border bg-surface p-2 text-sm">{hint}</p>}
      <div className="grid gap-3 md:grid-cols-[18rem_1fr]">
        <nav aria-label={t("files")} className="max-h-[70vh] overflow-auto rounded-md border border-border p-2">
          <ul>{render(root)}</ul>
          {all.length === 0 && <p className="text-sm text-muted">{t("empty")}</p>}
          {editable && (
            <form
              className="mt-3 flex gap-1"
              onSubmit={(e) => {
                e.preventDefault();
                addFile();
              }}
            >
              <label className="sr-only" htmlFor="newfile">
                {t("newFile")}
              </label>
              <input id="newfile" value={newPath} onChange={(e) => setNewPath(e.target.value)} placeholder="policies/tenant/x.yaml" className="min-w-0 flex-1 rounded-md border border-border bg-surface px-2 py-1 font-mono text-xs" />
              <button type="submit" className={button} disabled={!newPath.trim()}>
                {t("add")}
              </button>
            </form>
          )}
        </nav>

        <section aria-label={t("editor")} className="min-w-0 space-y-2">
          {current === null ? (
            <p className="rounded-md border border-border p-6 text-sm text-muted">{t("pick")}</p>
          ) : (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="break-all font-mono text-sm">{current}</h2>
                {editable && (
                  <div className="flex gap-2">
                    {current in edits && edits[current] !== null && files.some((f) => f.path === current) && (
                      <button type="button" className={button} onClick={() => revert(current)}>
                        {t("revert")}
                      </button>
                    )}
                    <button type="button" className={`${button} text-danger`} onClick={() => remove(current)}>
                      {t("delete")}
                    </button>
                  </div>
                )}
              </div>
              {binary ? (
                <p className="rounded-md border border-border p-6 text-sm text-muted">{t("binary")}</p>
              ) : (
                <div className="overflow-hidden rounded-md border border-border" style={{ height: "60vh" }}>
                  <Monaco
                    path={current}
                    language={languageOf(current)}
                    value={value}
                    theme={dark ? "vs-dark" : "vs"}
                    onChange={(v) => editable && change(current, v ?? "")}
                    options={{ readOnly: !editable, minimap: { enabled: false }, scrollBeyondLastLine: false, fontFamily: "var(--font-mono, monospace)", fontSize: 13, tabSize: 2, insertSpaces: true, ariaLabel: current, automaticLayout: true }}
                  />
                </div>
              )}
            </>
          )}

          <div aria-live="polite" className="text-sm">
            {check.state === "checking" && <p className="text-muted">{t("checking")}</p>}
            {check.state === "ok" && <p className="text-ok">{t("valid")}</p>}
            {check.state === "bad" && (
              <div role="alert" className="space-y-1 rounded-md border border-danger p-2">
                <p className="font-medium text-danger">{t("problems")}</p>
                <ul className="list-disc pl-5">
                  {check.errors.map((e) => (
                    <li key={e} className="break-all font-mono text-xs">
                      {e}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {editable && (
            <div className="space-y-2 rounded-md border border-border p-3">
              <h3 className="text-sm font-medium">{t("changes", { count: dirty.length })}</h3>
              {dirty.length > 0 && (
                <ul className="text-xs">
                  {dirty.map((p) => (
                    <li key={p} className="font-mono">
                      {edits[p] === null ? t("deleted") : files.some((f) => f.path === p) ? t("modified") : t("added")} · {p}
                    </li>
                  ))}
                </ul>
              )}
              <label className="block text-sm" htmlFor="message">
                {t("message")}
              </label>
              <input id="message" value={message} onChange={(e) => setMessage(e.target.value)} maxLength={500} className="w-full rounded-md border border-border bg-surface px-2 py-1.5 text-sm" />
              <button type="button" onClick={commit} disabled={busy || dirty.length === 0 || !message.trim() || check.state !== "ok"} className="rounded-md bg-action px-3 py-1.5 text-sm font-medium text-action-fg disabled:opacity-50">
                {busy ? t("committing") : kind === "git" ? t("commitBranch") : t("commitWrite")}
              </button>
              <p className="text-xs text-muted">{kind === "git" ? t("branchHelp") : t("directoryHelp")}</p>
              {error && (
                <p role="alert" className="whitespace-pre-wrap text-sm text-danger">
                  {error}
                </p>
              )}
              {done && (
                <p role="status" className="text-sm text-ok">
                  {done.branch ? t("pushed", { branch: done.branch, count: done.files }) : t("written", { count: done.files })}
                </p>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
