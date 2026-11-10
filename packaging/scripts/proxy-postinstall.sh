#!/bin/sh
# Post-install of the delbert-proxy package (deb and rpm; see packaging/nfpm).
set -e

chown root:delbert-proxy /etc/delbert/proxy.env
chmod 0640 /etc/delbert/proxy.env

# A new unit file, or a new binary behind a running service.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-restart delbert-proxy.service || true
fi
