#!/bin/sh
# Pre-install of the delbert-core package (deb and rpm; see packaging/nfpm).
set -e

# The service account (no login, no home of its own).
if ! getent group delbert >/dev/null; then
    groupadd --system delbert
fi
if ! getent passwd delbert >/dev/null; then
    useradd --system --gid delbert --home-dir /var/lib/delbert-core --no-create-home --shell /usr/sbin/nologin delbert
fi
