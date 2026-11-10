#!/bin/sh
# Pre-install of the delbert-proxy package (deb and rpm; see packaging/nfpm).
set -e

# The service account (no login, no home of its own).
if ! getent group delbert-proxy >/dev/null; then
    groupadd --system delbert-proxy
fi
if ! getent passwd delbert-proxy >/dev/null; then
    useradd --system --gid delbert-proxy --home-dir /var/lib/delbert-proxy --no-create-home --shell /usr/sbin/nologin delbert-proxy
fi
