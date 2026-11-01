// Serves Monaco from this site: the browser never loads it from a CDN (strict CSP, air-gapped installs).
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";

const from = "node_modules/monaco-editor/min/vs";
const to = "public/monaco/vs";
if (!existsSync(from)) {
  console.error("monaco-editor is not installed: run npm ci");
  process.exit(1);
}
rmSync("public/monaco", { recursive: true, force: true });
mkdirSync("public/monaco", { recursive: true });
cpSync(from, to, { recursive: true });
console.log("monaco -> public/monaco/vs");
