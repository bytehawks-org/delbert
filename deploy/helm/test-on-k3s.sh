#!/bin/sh
# Install the Helm chart on a real cluster and prove it end to end (docs/TESTING.md "The chart
# on K3s"; run by the `kubernetes` CI job on a single-node K3s). It creates the keys and the
# Secret, installs the chart, waits for every pod, calls the API through the LoadBalancer
# Service, enrolls an agent that runs outside the cluster (on this machine, in a sandbox root),
# then upgrades the release and checks that nothing was regenerated.
#
#   deploy/helm/test-on-k3s.sh <registry> <tag> <delbert-pki> <delbert-agent>
#
# Needs kubectl and helm pointed at the cluster, curl and jq, and the two names below resolving
# to the address the cluster's LoadBalancer Services answer on (the node, on K3s).
set -eu

REGISTRY="${1:?image registry, e.g. localhost}"
TAG="${2:?image tag}"
PKI="${3:?path of delbert-pki}"
AGENT="${4:?path of delbert-agent}"
CORE_HOST="${CORE_HOST:-delbert.example.com}"
NATS_HOST="${NATS_HOST:-nats.example.com}"
NS=delbert
CHART="$(cd "$(dirname "$0")" && pwd)/delbert"
WORK="$(mktemp -d)"
API="https://$CORE_HOST:8443"

AGENT_PID=""
finish() {
    code=$?
    [ -z "$AGENT_PID" ] || kill "$AGENT_PID" 2>/dev/null || true
    if [ "$code" -ne 0 ]; then
        echo "== FAILED: state of the namespace"
        kubectl -n "$NS" get pods,svc,pvc -o wide || true
        kubectl -n "$NS" describe pods | tail -60 || true
        for app in core nats postgresql web; do
            echo "-- logs: $app"
            kubectl -n "$NS" logs -l "app.kubernetes.io/component=$app" --tail=30 || true
        done
        [ ! -f "$WORK/agent.log" ] || tail -20 "$WORK/agent.log"
    fi
    rm -rf "$WORK"
    exit "$code"
}
trap finish EXIT

echo "== keys and Secret"
"$PKI" --dir "$WORK/keys" bootstrap --core-dns "$CORE_HOST" --core-dns delbert-core --nats-dns "$NATS_HOST" --nats-dns delbert-nats >/dev/null
kubectl create namespace "$NS"
kubectl -n "$NS" create secret generic delbert-pki --from-file="$WORK/keys/"

echo "== helm install"
helm install delbert "$CHART" -n "$NS" \
    --set image.registry="$REGISTRY" --set image.tag="$TAG" \
    --set core.publicUrl="$API" --set nats.publicUrl="tls://$NATS_HOST:4222" \
    --set core.mfaRequired=none \
    --wait --timeout 8m
kubectl -n "$NS" get pods

call() { curl -fsS --max-time 15 --cacert "$WORK/keys/ca.pem" "$@"; }

echo "== the API through the LoadBalancer Service"
i=0
until call "$API/healthz" >/dev/null 2>&1; do
    i=$((i + 1))
    [ $i -lt 30 ] || { echo "the Core does not answer at $API"; exit 1; }
    sleep 2
done
call "$API/healthz"
echo

PASSWORD="$(kubectl -n "$NS" get secret delbert-env -o jsonpath='{.data.DELBERT_BOOTSTRAP_ADMIN_PASSWORD}' | base64 -d)"
TOKEN="$(call -X POST "$API/v1/auth/login" -H 'content-type: application/json' -d "{\"username\":\"admin\",\"password\":\"$PASSWORD\"}" | jq -r .token)"
auth() { call -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"; }

echo "== a tenant, a policy, an enrollment key"
auth -X POST "$API/v1/tenants" -d '{"name":"acme"}' >/dev/null
cat >"$WORK/policy.yaml" <<'YAML'
apiVersion: delbert/v1
kind: Policy
metadata: { name: base, tenant: acme }
spec:
  target: { groups: [web] }
  resources:
    - id: motd
      copy: { content: "managed by delbert on k3s\n", dest: /etc/motd, mode: "0644" }
YAML
auth -X POST "$API/v1/tenants/acme/policies" -d "$(jq -n --rawfile y "$WORK/policy.yaml" '{yaml:$y}')"
echo
PSK="$(auth -X POST "$API/v1/tenants/acme/enrollment-keys" -d '{"groups":["web"],"max_uses":1}' | jq -r .key)"

echo "== an agent outside the cluster"
mkdir -p "$WORK/root/etc" "$WORK/state"
DELBERT_CORE_URL="$API" DELBERT_CA_FILE="$WORK/keys/ca.pem" DELBERT_ENROLL_PSK="$PSK" DELBERT_AGENT_ID=outside-01 \
    "$AGENT" run --identity-dir "$WORK/state/identity" --state-dir "$WORK/state" --root "$WORK/root" --interval-secs 5 >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
compliant() { auth "$API/v1/tenants/acme/agents" | jq -e '.[] | select(.name == "outside-01" and .compliant == true and .reported_version == 1)' >/dev/null; }
i=0
until compliant; do
    i=$((i + 1))
    [ $i -lt 30 ] || { echo "the agent did not report as compliant"; exit 1; }
    sleep 2
done
test "$(cat "$WORK/root/etc/motd")" = "managed by delbert on k3s"
echo "agent outside-01 enrolled, policy applied, reported compliant"

echo "== helm upgrade keeps passwords, data and agents"
before="$(kubectl -n "$NS" get secret delbert-env -o jsonpath='{.data}' | sha256sum)"
helm upgrade delbert "$CHART" -n "$NS" --reuse-values --set web.replicas=1 --set core.apiDocs=true --wait --timeout 8m
after="$(kubectl -n "$NS" get secret delbert-env -o jsonpath='{.data}' | sha256sum)"
test "$before" = "$after" || { echo "the generated passwords changed on upgrade"; exit 1; }
i=0
until call "$API/healthz" >/dev/null 2>&1; do
    i=$((i + 1))
    [ $i -lt 30 ] || { echo "the Core does not answer after the upgrade"; exit 1; }
    sleep 2
done
TOKEN="$(call -X POST "$API/v1/auth/login" -H 'content-type: application/json' -d "{\"username\":\"admin\",\"password\":\"$PASSWORD\"}" | jq -r .token)"
auth "$API/v1/audit/verify"
echo
# The Core restarted (its configuration changed): the agent must find it again by itself.
applied="$(grep -c 'applied policy' "$WORK/agent.log" || true)"
i=0
until [ "$(grep -c 'applied policy' "$WORK/agent.log" || true)" -gt "$applied" ] && compliant; do
    i=$((i + 1))
    [ $i -lt 40 ] || { echo "the agent did not come back after the upgrade"; exit 1; }
    sleep 3
done
kubectl -n "$NS" get pods
echo "CHART-OK"
