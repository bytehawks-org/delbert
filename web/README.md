# Delbert web

Administration UI: Next.js 16 (App Router), React 19, Tailwind CSS 4, TypeScript. Design and milestones: [docs/FRONTEND.md](../docs/FRONTEND.md).

The browser talks only to this server (a backend-for-frontend). The Core's session token lives in an encrypted, `HttpOnly`, `SameSite=Strict` cookie that only this server can open; every Core call is made from the server with a client generated from the Core's OpenAPI document. Strict CSP with a per-request nonce, `Origin` check on state-changing routes, no external fonts, scripts or analytics.

## Develop (no Node needed on the host)

```sh
cd web
podman run --rm -v "$PWD":/web:Z -w /web docker.io/library/node:22-slim npm install
podman run --rm -v "$PWD":/web:Z -w /web docker.io/library/node:22-slim npm run typecheck
```

The API types are generated from `openapi.json`, which the Core prints without a database: `delbert-core --print-openapi > web/openapi.json && npm run gen:api` (commit both; a Core change that breaks the UI shows up as a type error).

## Run and test against a Core

The e2e compose stack starts the Core and this UI (see [docs/TESTING.md](../docs/TESTING.md)); then

```sh
podman run --rm --network delbert_default -e WEB_URL=http://web:3000 -e CORE_URL=https://core:8080 \
  -e NODE_EXTRA_CA_CERTS=/pki/ca.pem -v "$PWD/../dev/pki/ca.pem":/pki/ca.pem:ro,Z \
  -v "$PWD":/web:Z -w /web mcr.microsoft.com/playwright:v1.64.1-noble npx playwright test
```

## Configuration (environment)

| Variable | Meaning |
|----------|---------|
| `DELBERT_CORE_URL` | where this server reaches the Core (default `http://localhost:8080`); the Core's CA must be trusted by Node (`NODE_EXTRA_CA_CERTS`) |
| `WEB_CORE_PUBLIC_URL` | where the browser reaches the Core, for single sign-on redirects (default: `DELBERT_CORE_URL`) |
| `WEB_SESSION_SECRET` | 32 bytes, base64url: encrypts the session cookie (required in production) |
| `WEB_PUBLIC_URL` | the UI's public URL, when behind a reverse proxy that does not forward `Host`/`X-Forwarded-*` |
| `WEB_STALE_MINUTES` | dashboard: an agent or proxy silent for longer than this is shown as silent (default 10) |
| `WEB_JS_BUDGET` | performance test: JavaScript bytes on the wire per screen (default 200000) |
| `WEB_INSECURE_COOKIES` | `true` drops the `Secure` flag (plain-HTTP development only) |

For single sign-on set the Core's `DELBERT_UI_URL` to `<UI URL>/auth/callback` and `DELBERT_PUBLIC_URL` to the Core's public address.
