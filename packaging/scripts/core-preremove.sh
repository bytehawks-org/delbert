#!/bin/sh
# Pre-remove of the delbert-core package (deb and rpm; see packaging/nfpm).
set -e

# Stop and disable on removal only: deb passes "remove", rpm passes 0 (an upgrade passes "upgrade" / 1).
case "$1" in
    remove | 0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now delbert-core.service || true
        fi
        ;;
esac
