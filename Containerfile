# Builds the Delbert binaries and two runtime images:
#   podman build --target core  -t localhost/delbert-core  .
#   podman build --target agent -t localhost/delbert-agent .
FROM docker.io/library/rust:1 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace \
 && mkdir /out \
 && cp target/release/delbert-core target/release/delbert-agent target/release/delbert-sign target/release/delbert-proxy /out/

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
