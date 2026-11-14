#!/bin/sh
# Install the freshly built packages in clean Debian and Fedora containers and check what they
# lay down (used by the CI workflow after packaging/build-packages.sh).
#
#   packaging/test-packages.sh [directory with the packages] [container engine]
set -eu

DIST="$(cd "${1:-dist}" && pwd)"
ENGINE="${2:-docker}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 0755 "$WORK"

cat >"$WORK/policy.yaml" <<'YAML'
apiVersion: delbert/v1
kind: Policy
metadata: { name: packages, tenant: t1 }
spec:
  resources:
    - id: motd
      copy: { content: "installed from a package\n", dest: /etc/motd, mode: "0644" }
YAML

cat >"$WORK/checks.sh" <<'CHECKS'
set -eu
delbert-agent --version
# The aliases: one executable, two families of commands.
test "$(readlink -f /usr/bin/delbert)" = "$(readlink -f /usr/bin/delbert-agent)"
test "$(readlink -f /usr/bin/dg)" = "$(readlink -f /usr/bin/delbert-agent)"
test "$(readlink -f /usr/bin/overlook)" = "$(readlink -f /usr/bin/delbert-agent)"
overlook --help | grep -q check
# A negated command would not trip `set -e`: test it explicitly.
if overlook --help | grep -q apply; then echo "overlook must not offer apply" >&2; exit 1; fi
dg --help | grep -q apply
delbert-core --print-openapi >/dev/null
delbert-proxy --help >/dev/null
delbert-pki --version
delbert-sign --help >/dev/null
# Units, configuration with the right modes, service accounts, state directories.
test -f /usr/lib/systemd/system/delbert-agent.service
test -f /usr/lib/systemd/system/delbert-core.service
test -f /usr/lib/systemd/system/delbert-proxy.service
test "$(stat -c %a /etc/delbert/agent.env)" = 600
test "$(stat -c %a:%U:%G /etc/delbert/core.env)" = 640:root:delbert
test "$(stat -c %a:%U:%G /etc/delbert/proxy.env)" = 640:root:delbert-proxy
test "$(stat -c %a:%U:%G /etc/delbert/keys)" = 750:root:delbert
test "$(stat -c %U /var/lib/delbert-core)" = delbert
test "$(stat -c %U /var/lib/delbert-proxy)" = delbert-proxy
# The packaged configuration is accepted once the keys exist (docs/install.md "Linux packages").
delbert-pki --dir /etc/delbert/keys bootstrap --core-dns delbert.example.com --nats-dns delbert.example.com >/dev/null
chgrp delbert /etc/delbert/keys/*.key /etc/delbert/keys/nats-issuer.seed
chmod 0640 /etc/delbert/keys/*.key /etc/delbert/keys/nats-issuer.seed
set -a
. /etc/delbert/core.env
set +a
delbert-core --config /etc/delbert/core.toml --check-config >/dev/null
# The agent works on this system (sandbox root: nothing outside /tmp is touched).
mkdir -p /tmp/root/etc
code=0; overlook check /t/policy.yaml --root /tmp/root || code=$?
test "$code" -eq 2
test ! -e /tmp/root/etc/motd
dg apply /t/policy.yaml --root /tmp/root
overlook check /t/policy.yaml --root /tmp/root
echo PACKAGES-OK
CHECKS

echo "== debian:13 (deb)"
"$ENGINE" run --rm -v "$DIST":/dist:ro -v "$WORK":/t:ro docker.io/library/debian:13-slim sh -ec '
    dpkg -i /dist/delbert-tools_*_amd64.deb /dist/delbert-agent_*_amd64.deb /dist/delbert-core_*_amd64.deb /dist/delbert-proxy_*_amd64.deb
    sh /t/checks.sh
    dpkg -r delbert-agent delbert-proxy delbert-core delbert-tools'

echo "== fedora (rpm)"
"$ENGINE" run --rm -v "$DIST":/dist:ro -v "$WORK":/t:ro docker.io/library/fedora:latest sh -ec '
    rpm -i /dist/delbert-tools-*.x86_64.rpm /dist/delbert-agent-*.x86_64.rpm /dist/delbert-core-*.x86_64.rpm /dist/delbert-proxy-*.x86_64.rpm
    sh /t/checks.sh
    rpm -e delbert-agent delbert-proxy delbert-core delbert-tools'
