# Delbert - Frontend

Administration web UI for the Core: tenants, agents, policies, secrets, artifacts, proxies, users and roles, audit. Status: **milestone M0 implemented** in [`web/`](../web) (skeleton, login through the backend-for-frontend with MFA and single sign-on, i18n, theme, generated client, container image, Playwright tests). **M1 (read-only views) and M2 (policy editor, version steps, enrollment keys, secrets, artifacts) are implemented too**; M3 onwards is design. Mutations go through one narrow allow-listed pass-through (`/api/core/...`, same-origin only) that adds the session on the server; the editor is a plain validated textarea with a diff (CodeMirror highlighting is a later refinement). The API additions this UI depends on ([RBAC.md](RBAC.md)) are in the Core.

## Stack

| Choice | Reason |
|--------|--------|
| **Next.js** (App Router) + **Tailwind CSS** | required by the project; both MIT |
| **TypeScript**, strict | the API is typed; generated client below |
| shadcn/ui components (Radix primitives) | MIT, copied into the repo (no runtime dependency to track), accessible by default |
| CodeMirror 6 for YAML | MIT, light; Monaco is the heavier alternative |
| `next-intl` | Italian and English, extensible (requirement) |
| TanStack Query for client-side state | only where data changes under the user's eyes (dashboard, live status) |
| Playwright | end-to-end tests against the `compose.e2e` stack |

No external CDN, fonts or analytics: everything is served from the same origin (strict CSP, and an isolated-network deployment must work).

## Backend-for-frontend (BFF)

```text
 browser ──cookie──▶ delbert-web (Next.js) ──bearer──▶ delbert-core API
```

- The browser only talks to Next.js. Login is a route handler that calls the Core, stores the session token **server-side or in an encrypted `HttpOnly` cookie**, and never exposes it to JavaScript. Every API call is made from Server Components or route handlers.
- Consequences: no CORS on the Core, XSS cannot steal the session, CSRF protection lives in one place (double-submit token + `SameSite=Strict`), and the Core API surface that must be public is just what the BFF needs.
- Alternative considered: a static SPA calling the Core directly with the token in memory. Simpler to host, but the token is reachable by any script and CORS must be opened. Rejected for an administration console.
- `delbert-web` is a separate container (`next build` standalone output), deployed next to the Core on Kubernetes/K3s behind the same ingress; Podman for development, like the rest.

## Generated client

`/openapi.json` (utoipa) is the contract. `openapi-typescript` + `openapi-fetch` generate types and a client in CI; the build fails if the Core's spec changes incompatibly. Endpoints missing from the spec are fixed in the Core, not worked around in the UI.

## Screens

Ordered by value; each maps to an existing or planned API.

| Screen | Content | API status |
|--------|---------|------------|
| Login, MFA, profile | password, TOTP, sessions, API tokens, language | MFA/tokens: [RBAC.md](RBAC.md) |
| Dashboard | agents compliant/drifted/unreachable, proxies health, recent changes, conflicts | needs aggregated counts + SSE |
| Tenants | list, create, settings (approval), delete | delete missing |
| Agents | list with filters (group, proxy, compliance), detail: last report **per resource**, groups, certificate expiry, proxy, effective version vs reported | pagination/filters; report detail |
| Enrollment | keys with TTL/uses/groups, one-time display, revoke | exists |
| Policies | list, **YAML editor with JSON Schema validation**, version history and diff, impact/conflict preview, submit/approve/activate/rollback | schema endpoint, versions, diff, approval, preview |
| Secrets | names, set (write-only form, never displayed back), delete | exists |
| Artifacts | upload, versions, hashes, where used | usage lookup |
| Proxies | create (one-time key), status, agents, last seen | exists |
| Users and roles | users, MFA state, assignments with scope, **permission matrix** editor | RBAC v2 |
| Audit | search and filter, event detail, chain verification, export | `GET /v1/audit` missing |

UI rules that follow from the product: secret values are never rendered; destructive actions ask for the target name; every list has an empty, loading and error state; what the user cannot do is hidden **and** enforced by the API (the UI is never the security boundary); permission checks use `/v1/me` per tenant.

## Cross-cutting

- **i18n**: all strings in message catalogs (`it`, `en`), dates and numbers localized, no concatenated sentences. Language from the profile, then the browser.
- **Accessibility**: WCAG 2.1 AA target, keyboard-complete forms and tables, visible focus, reduced motion, light/dark themes.
- **Security headers**: strict CSP (nonce), `frame-ancestors 'none'`, `Referrer-Policy`, HSTS behind TLS. Markdown or HTML from the API is never rendered as HTML.
- **Live status**: Server-Sent Events from the Core for the dashboard and agent detail (a plain stream of "agent X changed", the UI refetches); polling as a fallback.
- **Errors**: the API's `{"error": "..."}` is shown translated where the code is known, verbatim otherwise; 401 redirects to login, 403 explains the missing permission.
- **Observability**: request IDs from the Core shown on error pages; no third-party telemetry.

## Delivery plan

1. **M0 - skeleton**: Next.js app in `web/`, Containerfile target `web`, compose service, generated client in CI, login through the BFF, layout, i18n and theme, Playwright smoke test against the e2e stack.
2. **M1 - read-only (implemented)**: dashboard, tenants, agents (list/detail), policies (list, read-only YAML), proxies, audit browser.
3. **M2 - operations (implemented, except agent/proxy management, which is still API-only)**: enrollment keys, secrets, artifacts, agent and proxy management, policy editor with validation and versions.
4. **M3 - governance**: users, roles and the permission matrix, tenant settings, approval workflow, MFA, API tokens.
5. **M4 - hardening**: SSO login, SSE, accessibility audit, performance budget, visual regression.

Each milestone is usable on its own and ships with its Playwright scenarios; Core changes it needs are listed in [ROADMAP.md](ROADMAP.md) and land first.

## Open points

- Component library: shadcn/ui is the default; revisit only if its maintenance model becomes a problem.
- Whether the BFF keeps sessions server-side (needs a small store, e.g. Redis, already an optional component) or in an encrypted cookie (stateless, larger cookies). Default: encrypted cookie, switch if sessions need server-side revocation beyond what the Core already offers.
- Whether the dashboard needs time-series history (then a metrics store is required) or only current state.
