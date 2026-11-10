#!/bin/sh
# Post-install of the delbert-core package (deb and rpm; see packaging/nfpm).
set -e

# Secrets and keys are readable by the service account only (never world-readable).
chown root:delbert /etc/delbert/core.env
chmod 0640 /etc/delbert/core.env
if [ ! -d /etc/delbert/keys ]; then
    install -d -m 0750 -o root -g delbert /etc/delbert/keys
fi

# A new unit file, or a new binary behind a running service.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-restart delbert-core.service || true
fi

if [ ! -f /etc/delbert/keys/ca.pem ]; then
    echo "delbert-core: create the keys (delbert-pki --dir /etc/delbert/keys bootstrap ...), edit"
    echo "              /etc/delbert/core.toml and /etc/delbert/core.env, then: systemctl enable --now delbert-core"
    echo "              (docs/install.md, \"Linux packages\")"
fi
