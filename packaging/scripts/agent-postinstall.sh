#!/bin/sh
# Post-install of the delbert-agent package (deb and rpm; see packaging/nfpm).
set -e

# A new unit file, or a new binary behind a running service.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-restart delbert-agent.service || true
fi

if [ ! -d /var/lib/delbert/identity ]; then
    echo "delbert-agent: set the Core URL, the agent name and the enrollment key in /etc/delbert/agent.env,"
    echo "               put the Delbert CA in /etc/delbert/ca.pem, then: systemctl enable --now delbert-agent"
fi
