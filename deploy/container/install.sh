#!/bin/sh
# Install or upgrade the Delbert control plane on this host with Podman or Docker
# (docs/install.md "Containers"). Run it in the directory that holds compose.yaml:
#
#   ./install.sh --host delbert.example.com
#
# Options:
#   --host NAME       DNS name agents and users use for this host (required the first time)
#   --version X.Y.Z   image tag (default: the one in .env, else the release of this bundle)
#   --registry REG    image registry (default: ghcr.io/bytehawks-org)
#   --no-web          do not start the administration UI
#   --no-pull         use the images already present on this host
#
# The first run writes `.env` with random passwords and starts the stack; the keys are created
# in the `keys` volume. Later runs keep `.env` and the keys: use them to upgrade (--version).
set -eu

cd "$(dirname "$0")"
# The release workflow sets this to the version the bundle was published with.
DEFAULT_VERSION=latest
HOST=""
VERSION=""
REGISTRY=""
WEB=1
PULL=1

die() {
    echo "install: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --registry) REGISTRY="$2"; shift 2 ;;
        --no-web) WEB=0; shift ;;
        --no-pull) PULL=0; shift ;;
        -h | --help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1" ;;
    esac
done

if command -v podman >/dev/null 2>&1 && podman compose version >/dev/null 2>&1; then
    ENGINE=podman
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    ENGINE=docker
else
    die "podman (with a compose provider) or docker (with the compose plugin) is required"
fi
compose() { "$ENGINE" compose "$@"; }

random_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

if [ ! -f .env ]; then
    [ -n "$HOST" ] || die "--host is required for the first installation"
    ADMIN_PASSWORD="$(random_hex 12)"
    umask 077
    {
        echo "# Written by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Keep this file private (mode 0600)."
        echo "DELBERT_REGISTRY=${REGISTRY:-ghcr.io/bytehawks-org}"
        echo "DELBERT_VERSION=${VERSION:-$DEFAULT_VERSION}"
        echo "# The name in the certificates of the Core and of NATS: agents must use it."
        echo "DELBERT_HOST=$HOST"
        echo "DELBERT_CORE_PORT=8443"
        echo "DELBERT_NATS_PORT=4222"
        echo "# The UI speaks plain HTTP on 127.0.0.1:3000. Put a TLS reverse proxy in front of it and"
        echo "# set its public address here; for a trial without TLS set WEB_INSECURE_COOKIES=true."
        echo "DELBERT_WEB_BIND=127.0.0.1"
        echo "DELBERT_WEB_PORT=3000"
        echo "DELBERT_WEB_URL=http://localhost:3000"
        echo "WEB_INSECURE_COOKIES=false"
        echo "WEB_SESSION_SECRET=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
        echo "POSTGRES_PASSWORD=$(random_hex 24)"
        echo "POSTGRES_RT_PASSWORD=$(random_hex 24)"
        echo "NATS_AUTH_PASSWORD=$(random_hex 24)"
        echo "# First start only: the password of the user \"admin\". Change it after the first login,"
        echo "# enable MFA, then empty this line."
        echo "DELBERT_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD"
    } >.env
    FIRST=1
else
    FIRST=0
    # An upgrade: only the image tag and registry may change.
    [ -z "$VERSION" ] || sed -i "s|^DELBERT_VERSION=.*|DELBERT_VERSION=$VERSION|" .env
    [ -z "$REGISTRY" ] || sed -i "s|^DELBERT_REGISTRY=.*|DELBERT_REGISTRY=$REGISTRY|" .env
fi

SERVICES="postgres nats core"
[ "$WEB" -eq 0 ] || SERVICES="$SERVICES web"

if [ "$PULL" -eq 1 ]; then
    # shellcheck disable=SC2086
    compose pull init $SERVICES
fi
# shellcheck disable=SC2086
compose up -d $SERVICES

# shellcheck disable=SC1091
. ./.env

# The CA certificate is public: agents need it to enroll. Reading it also tells that the
# Core's container is up.
i=0
until compose exec -T core cat /keys/ca.pem >ca.pem 2>/dev/null && [ -s ca.pem ]; do
    i=$((i + 1))
    [ $i -lt 60 ] || die "the Core's container did not start: $ENGINE compose logs core"
    sleep 2
done
chmod 0644 ca.pem
# The Core answers on its health endpoint once the migrations have run.
if command -v curl >/dev/null 2>&1; then
    i=0
    # Straight to this host: never through a proxy from the environment.
    until curl -fsS -o /dev/null --max-time 5 --noproxy '*' --cacert ca.pem --resolve "$DELBERT_HOST:$DELBERT_CORE_PORT:127.0.0.1" "https://$DELBERT_HOST:$DELBERT_CORE_PORT/healthz"; do
        i=$((i + 1))
        [ $i -lt 60 ] || die "the Core does not answer: $ENGINE compose logs core"
        sleep 2
    done
fi

echo
echo "Delbert is running ($ENGINE compose ps)."
echo "  Core API : https://$DELBERT_HOST:$DELBERT_CORE_PORT   (certificate of the Delbert CA: ./ca.pem)"
echo "  NATS     : tls://$DELBERT_HOST:$DELBERT_NATS_PORT     (agents connect here)"
[ "$WEB" -eq 0 ] || echo "  Web UI   : http://$DELBERT_WEB_BIND:$DELBERT_WEB_PORT          (publish it through a TLS reverse proxy)"
if [ "$FIRST" -eq 1 ]; then
    echo "  Login    : admin / $ADMIN_PASSWORD"
    echo "             change the password, enable MFA, then empty DELBERT_BOOTSTRAP_ADMIN_PASSWORD in .env"
    echo "  Keys     : in the volume delbert_keys: back it up offline now (docs/install.md \"Backup\")"
fi
