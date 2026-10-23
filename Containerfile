# Builds the Delbert binaries and two runtime images:
#   podman build --target core  -t localhost/delbert-core  .
#   podman build --target agent -t localhost/delbert-agent .
#   podman build --target proxy -t localhost/delbert-proxy .
#   podman build --target web   -t localhost/delbert-web   .   # administration UI (Next.js)
#   podman build --target tools -t localhost/delbert-tools .   # delbert-pki and delbert-sign, to bootstrap keys
FROM docker.io/library/rust:1 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace \
 && mkdir /out \
 && cp target/release/delbert-core target/release/delbert-agent target/release/delbert-sign target/release/delbert-proxy target/release/delbert-pki /out/

FROM docker.io/library/debian:13-slim AS core
# git: content sources of kind "git" (docs/CONTENT.md). The Core runs it on its own host, never on managed systems.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home delbert
COPY --from=build /out/delbert-core /usr/local/bin/delbert-core
# Local artifact store (DELBERT_ARTIFACT_STORE=local); mount a volume here, or use s3.
RUN mkdir -p /var/lib/delbert-core/artifacts /var/lib/delbert-core/content && chown -R 10001 /var/lib/delbert-core
ENV DELBERT_ARTIFACT_DIR=/var/lib/delbert-core/artifacts DELBERT_CONTENT_DIR=/var/lib/delbert-core/content
VOLUME /var/lib/delbert-core
USER 10001
EXPOSE 8080
ENTRYPOINT ["delbert-core"]

# The agent runs as root: it changes the host it runs on (a container here).
FROM docker.io/library/debian:13-slim AS agent
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/delbert-agent /usr/local/bin/delbert-agent
COPY --from=build /out/delbert-sign /usr/local/bin/delbert-sign
VOLUME /var/lib/delbert
ENTRYPOINT ["delbert-agent", "run"]

# The proxy relays for the agents of a branch office (no changes to the host it runs on).
FROM docker.io/library/debian:13-slim AS proxy
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/delbert-proxy /usr/local/bin/delbert-proxy
VOLUME /var/lib/delbert-proxy
EXPOSE 8443
ENTRYPOINT ["delbert-proxy", "run"]

# Administration tools: the internal CA / key generation (delbert-pki) and the signing-key tool (delbert-sign).
FROM docker.io/library/debian:13-slim AS tools
COPY --from=build /out/delbert-pki /usr/local/bin/delbert-pki
COPY --from=build /out/delbert-sign /usr/local/bin/delbert-sign

# Administration UI: a Next.js backend-for-frontend. The browser only talks to this server, which holds the
# Core session in an encrypted HttpOnly cookie. docs/FRONTEND.md.
FROM docker.io/library/node:22-slim AS web-build
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# The build never needs the real secret: pages are rendered on demand.
RUN WEB_SESSION_SECRET=build-time-placeholder-not-used npm run build

FROM docker.io/library/node:22-slim AS web
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0 NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
COPY --from=web-build /web/.next/standalone ./
COPY --from=web-build /web/.next/static ./.next/static
COPY --from=web-build /web/public ./public
USER node
EXPOSE 3000
CMD ["node", "server.js"]
