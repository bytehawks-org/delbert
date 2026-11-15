#!/bin/sh
# Install the Delbert agent on a Linux host from the published packages, configure it and
# start it (docs/install.md "Agents"). Run as root:
#
#   sh install-agent.sh --core-url https://delbert.example.com:8443 --ca-file ca.pem \
#                       --agent-id web-01 --psk <enrollment key>
#
# Options (or the environment variables in brackets):
#   --core-url URL    the Core, or the site's proxy                    [DELBERT_CORE_URL]
#   --ca-file FILE    the Delbert CA certificate (ca.pem)              [DELBERT_CA_FILE]
#   --ca-sha256 HEX   or only its SHA-256 fingerprint: the agent fetches the certificate from
#                     the Core and accepts it only if it matches       [DELBERT_CA_SHA256]
#   --agent-id NAME   name of this host in Delbert (default: hostname) [DELBERT_AGENT_ID]
#   --psk KEY         one-time enrollment key                          [DELBERT_ENROLL_PSK]
#   --version X.Y.Z   release to install (default: the latest)         [DELBERT_VERSION]
#   --package FILE    install this .deb/.rpm instead of downloading one
#   --signing-key FILE  public key the packages are signed with (delbert-signing-key.asc);
#                     downloaded with the package when not given
# Without --psk the package is installed and left unconfigured.
# The agent never listens: it only makes outbound connections to the Core and to NATS.
set -eu

REPO="${DELBERT_REPO:-bytehawks-org/delbert}"
CORE_URL="${DELBERT_CORE_URL:-}"
CA_FILE="${DELBERT_CA_FILE:-}"
CA_SHA256="${DELBERT_CA_SHA256:-}"
AGENT_ID="${DELBERT_AGENT_ID:-$(hostname -s 2>/dev/null || hostname)}"
PSK="${DELBERT_ENROLL_PSK:-}"
VERSION="${DELBERT_VERSION:-}"
PACKAGE=""
SIGNING_KEY=""

die() {
    echo "install-agent: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --core-url) CORE_URL="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        --ca-sha256) CA_SHA256="$2"; shift 2 ;;
        --agent-id) AGENT_ID="$2"; shift 2 ;;
        --psk) PSK="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --package) PACKAGE="$2"; shift 2 ;;
        --signing-key) SIGNING_KEY="$2"; shift 2 ;;
        -h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
if [ -n "$PSK" ]; then
    [ -n "$CORE_URL" ] || die "--core-url is required with --psk"
    if [ -n "$CA_FILE" ]; then
        [ -r "$CA_FILE" ] || die "cannot read $CA_FILE"
    else
        [ -n "$CA_SHA256" ] || die "--ca-file or --ca-sha256 is required with --psk (the Delbert CA)"
    fi
fi

case "$(uname -m)" in
    x86_64 | amd64) DEB_ARCH=amd64; RPM_ARCH=x86_64 ;;
    aarch64 | arm64) DEB_ARCH=arm64; RPM_ARCH=aarch64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac
if command -v dpkg >/dev/null 2>&1; then
    KIND=deb
elif command -v rpm >/dev/null 2>&1; then
    KIND=rpm
else
    die "neither dpkg nor rpm found: install the static binary by hand (docs/install.md)"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -z "$PACKAGE" ]; then
    command -v curl >/dev/null 2>&1 || die "curl is required to download the package (or use --package)"
    if [ -z "$VERSION" ]; then
        # The "latest" release redirects to its tag: .../releases/tag/vX.Y.Z
        VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/tag/v||')"
        [ -n "$VERSION" ] || die "cannot find the latest release of $REPO"
    fi
    VERSION="${VERSION#v}"
    if [ "$KIND" = deb ]; then
        FILE="delbert-agent_${VERSION}_${DEB_ARCH}.deb"
    else
        FILE="delbert-agent-${VERSION}-1.${RPM_ARCH}.rpm"
    fi
    BASE="https://github.com/$REPO/releases/download/v$VERSION"
    echo "downloading $FILE"
    curl -fsSL -o "$TMP/$FILE" "$BASE/$FILE"
    curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
    (cd "$TMP" && grep " $FILE\$" SHA256SUMS | sha256sum -c -) || die "checksum mismatch for $FILE"
    PACKAGE="$TMP/$FILE"
    # The key the release was signed with (absent from releases older than package signing).
    if [ -z "$SIGNING_KEY" ] && curl -fsSL -o "$TMP/delbert-signing-key.asc" "$BASE/delbert-signing-key.asc" 2>/dev/null; then
        (cd "$TMP" && grep " delbert-signing-key.asc\$" SHA256SUMS | sha256sum -c -) || die "checksum mismatch for the signing key"
        SIGNING_KEY="$TMP/delbert-signing-key.asc"
    fi
fi

if [ "$KIND" = deb ]; then
    dpkg -i "$PACKAGE"
else
    if [ -n "$SIGNING_KEY" ]; then
        # rpm verifies the package against the key before installing it.
        rpm --import "$SIGNING_KEY"
        rpm -U --replacepkgs "$PACKAGE"
    else
        # No key to verify with (an unsigned build, or --package without --signing-key): recent
        # rpm refuses that by default. A downloaded package was checked against SHA256SUMS above.
        echo "install-agent: no signing key: installing without signature verification" >&2
        rpm -U --replacepkgs --nosignature "$PACKAGE"
    fi
fi

if [ -z "$PSK" ]; then
    echo "installed; configure /etc/delbert/agent.env and /etc/delbert/ca.pem, then: systemctl enable --now delbert-agent"
    exit 0
fi

if [ -n "$CA_FILE" ]; then
    install -m 0644 "$CA_FILE" /etc/delbert/ca.pem
    CA_SETTING="DELBERT_CA_FILE=/etc/delbert/ca.pem"
else
    CA_SETTING="DELBERT_CA_SHA256=$CA_SHA256"
fi
# The file holds the enrollment key until the agent is enrolled: root only.
umask 077
{
    echo "# Written by install-agent.sh. The enrollment key is only needed for the first start"
    echo "# (the identity is then kept in /var/lib/delbert/identity)."
    echo "DELBERT_CORE_URL=$CORE_URL"
    echo "$CA_SETTING"
    echo "DELBERT_ENROLL_PSK=$PSK"
    echo "DELBERT_AGENT_ID=$AGENT_ID"
    echo "DELBERT_INTERVAL_SECS=300"
    echo "RUST_LOG=info"
} >/etc/delbert/agent.env
systemctl enable --now delbert-agent

# Enrollment happens at the first start: wait for the identity, then drop the key from the file.
i=0
while [ ! -f /var/lib/delbert/identity/meta.json ] && [ $i -lt 30 ]; do
    sleep 1
    i=$((i + 1))
done
if [ -f /var/lib/delbert/identity/meta.json ]; then
    sed -i 's/^DELBERT_ENROLL_PSK=.*/DELBERT_ENROLL_PSK=/' /etc/delbert/agent.env
    echo "agent '$AGENT_ID' enrolled and running (journalctl -u delbert-agent -f)"
else
    die "the agent did not enroll within 30 seconds: journalctl -u delbert-agent"
fi
