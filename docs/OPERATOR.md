# Delbert - Kubernetes Operator and configuration delivery

Component doc for `delbert-operator` and the Core side of configuration delivery. Design rationale: [ABSTRACT.md](ABSTRACT.md) §5. Core endpoints: [API.md](API.md). Status of each step: [ROADMAP.md](ROADMAP.md).

## Goal

Centralize environment variables, configuration files and secrets of containerized workloads in Delbert, without managing them in each deployment. Delivery is **per namespace/environment**, not per pod: containers are ephemeral, so they get no agent, no identity and no per-pod audit.

Not used on purpose: a sidecar agent with a reusable environment PSK (a long-lived secret in every deployment), per-pod identity with single-use tokens (audit per pod: disproportionate effort), workload authentication with projected ServiceAccount tokens (only useful if a workload must talk to the Core directly). They stay in the roadmap as deferred.

## How it fits together

```
Core ── deliveries (tenant, environment, operator identity, secrets, files)
  │  bundle: variables + files + secrets sealed to the Operator (age)
  ▼
Operator (in cluster, enrolled as an agent) ── applies ──▶ ConfigMap + Secret in the namespace
                                                         └▶ pods: envFrom / volumes
```

- The Operator is the **only** component talking to the Core. It acts on its own cluster (consistent with "only agents and the Operator execute, locally").
- Podman/Docker hosts follow a different path: the host agent resolves `env_from` / `secret_from` on the `container` resource ([POLICY.md](POLICY.md) "Containers"): variables as environment, secrets as read-only files, the container recreated when they change.

## Core side (implemented)

A *delivery* (table `deliveries`, migration `0021`) names an environment of a tenant and the enrolled identity allowed to fetch it. Administration: `GET|PUT|DELETE /v1/tenants/{t}/deliveries[/{name}]`, permissions `policies:read` / `policies:write` (a dedicated permission is on the roadmap), audited as `delivery.set` / `delivery.delete`.

```json
{ "agent": "op-1", "secrets": ["db"], "files": ["app.toml"] }
```

The bundle, `GET /v1/agent/{t}/{agent}/deliveries/{name}` with the agent proof (`Authorization: Delbert-Agent`, kind `delivery`, body = delivery name):

| Part | Content |
|------|---------|
| `variables` | Layered variables resolved over **global**, **tenant** and the **group named like the delivery** (the environment). Constants (`locked`) are honoured. Strings as they are, other JSON values as compact JSON. |
| `files` | Latest version of each listed artifact (tenant's own over the shared one), UTF-8 text, 256 KiB each and 768 KiB in total (a ConfigMap holds 1 MiB). |
| `sensitive` | Listed tenant secrets, decrypted by the Core and re-encrypted (age, base64) to the fetching identity only. |
| `version` | Unix seconds of the latest change among the inputs. Informational: a removal is not reflected. Decide on changes by content. |

Failure behaviour: an unknown delivery, or one that belongs to another identity, is `404` (same answer, no enumeration); a missing secret or file is `409`; bad content is `422`. **Never a partial bundle.**

## Operator side

### Implemented

- `DelbertBinding` custom resource (`delbert.bytehawks.io/v1alpha1`, namespaced, short name `dbind`). `delbert-operator crd` prints the CRD.

  ```yaml
  apiVersion: delbert.bytehawks.io/v1alpha1
  kind: DelbertBinding
  metadata: { name: app, namespace: shop }
  spec:
    tenant: acme
    environment: prod            # = delivery name = group of the variables
    configMapName: delbert-config   # default
    secretName: delbert-secret      # default
    restartWorkloads:
      - { kind: Deployment, name: web }
  ```

- `render`: a pure function from a resolved bundle to a `ConfigMap` (variables and files) and a `Secret` (sensitive values only).
  - Keys must match `[-._a-zA-Z0-9]`, at most 253 characters, not `.` or `..`, and be unique across variables, files and sensitive values (fail closed).
  - The **content hash** is an HMAC-SHA256 under a key held by the Operator, and it ignores the bundle version. It goes on the objects and on the pod templates of the restarted workloads, readable by whoever can read a Deployment, so a plain hash of a low-entropy secret could be brute-forced. Republishing identical content restarts nothing.

- **Identity** (`identity`): the Operator is an agent enrolled in **one tenant** (one Operator serves the bindings of that tenant; a binding for another tenant gets a status message, not a retry loop). Keys are generated in the pod; only the public parts go to the Core. The identity lives in a Kubernetes `Secret` of the Operator's namespace (`key.pem`, `enc.key`, `hash.key`, `tenant`, `agent`), so a rescheduled pod finds it. The first start needs an enrollment key (`DELBERT_ENROLL_PSK`); it is created with `create`, never overwritten. If the Secret is lost: delete it and enroll again with a new key.
- **Bundle fetch** (`core`): `GET .../deliveries/{environment}` with the agent proof over HTTPS, trusting only the Delbert CA. Sensitive values are opened with the Operator's age key; one that does not open fails the whole bundle.
- **Reconcile loop** (`reconcile`, `kube::runtime::Controller` on `DelbertBinding`): per binding, fetch → open → `render` → server-side apply of `ConfigMap` and `Secret` (field manager `delbert-operator`, forced, owner reference to the binding so deleting it removes them; a key removed upstream disappears from the objects) → stamp the content hash on the pod template of each `restartWorkloads` entry when it differs (Kubernetes then does its normal rolling update; a missing workload is logged, not fatal) → status (`observedVersion`, `contentHash`, `message`). On error only `message` changes, the last applied state is kept.
- **Trigger**: periodic resync (`DELBERT_RESYNC_SECS`, default 60, minimum 10) plus changes to the bindings. The Core does not push to the Operator yet. The loop does not watch the generated `ConfigMap`/`Secret` (that would need cluster-wide watch on Secrets): drift is repaired at the next resync.

### Configuration of `delbert-operator run`

| Variable | Meaning |
|----------|---------|
| `DELBERT_CORE_URL` | HTTPS URL of the Core |
| `DELBERT_CA_FILE` | Delbert CA (PEM), the only trust anchor |
| `DELBERT_ENROLL_PSK` | enrollment key, first start only |
| `DELBERT_OPERATOR_NAME` | name the Operator takes in the Core |
| `DELBERT_NAMESPACE` | namespace of the identity secret (default: the pod's) |
| `DELBERT_IDENTITY_SECRET` | secret name (default `delbert-operator-identity`) |
| `DELBERT_RESYNC_SECS` | resync period (default 60) |

### Deployment ([deploy/kubernetes/operator/](../deploy/kubernetes/operator/))

`kubectl apply -k deploy/kubernetes/operator` creates the namespace `delbert-system`, the CRD (generated by `delbert-operator crd`), the RBAC below and a single-replica Deployment (non-root, read-only root filesystem, no capabilities; one replica because there is no leader election). Before applying: set `DELBERT_CORE_URL` and `DELBERT_OPERATOR_NAME` in `deployment.yaml`, create the ConfigMap `delbert-ca` (key `ca.pem`) and the Secret `delbert-operator-enroll` (key `psk`, an enrollment key of the tenant to serve). Image: `podman build --target operator -t localhost/delbert-operator .`. If the Core is only reachable by a name that the cluster cannot resolve, add `hostAliases` to the Deployment (the test below did).

### Kubernetes permissions

`delbertbindings` (+`/status`): get, list, watch, patch; `configmaps`, `secrets`: get, create, patch (in the bound namespaces); `deployments`, `statefulsets`, `daemonsets`: get, patch; `secrets` in its own namespace: get, create. The manifests bind only the first group cluster-wide (reading bindings); the write permissions (`ClusterRole delbert-operator-delivery`) are bound with **one `RoleBinding` per served namespace**, because a cluster-wide write on Secrets is a broad grant.

### Not implemented yet

Console pages for deliveries, push notification instead of polling, several tenants per Operator. See [ROADMAP.md](ROADMAP.md).

### Verified on a real cluster

Run on 2026-11-01 on **K3s v1.31.14** (the minimum supported version) with a real Core (HTTPS, Delbert CA, PostgreSQL 17, NATS): see [TESTING.md](TESTING.md) "Operator on K3s". Checked: enrollment from the pod with a single-use key and identity reuse after a restart; `ConfigMap`/`Secret` content as expected (layered variables, file, secret opened by the Operator) and consumed by a pod through `envFrom` and a volume; owner reference and field manager; rollout of the workload when a variable changes and **no** rollout on idle resyncs; a missing secret in the Core leaves the objects and the last applied state untouched and reports the error in the status; a binding of another tenant gets the status message; a deleted `Secret` is recreated at the next resync; deleting the binding removes the generated objects. Not verified: other Kubernetes versions, `StatefulSet`/`DaemonSet` rollouts, several bound namespaces at scale, an Operator restart in the middle of a pass.

## Security notes (NIS2/GDPR)

- Sensitive values transit etcd as `Secret` objects: **encryption at rest of etcd is a prerequisite**, and RBAC on Secrets must be tight. The per-agent encryption of the Core ends at the Operator, which decrypts and writes the `Secret`. An external secret backend (External Secrets Operator, Apache 2.0) is an optional alternative.
- The audit trail has tenant/environment granularity: who changed a delivery (`delivery.set`), and which version the Operator applied to which namespace (`agent.delivery.applied`, actor `agent:<tenant>/<operator>`, target `<namespace>/<binding>`, one event per change of content, not per resync; `agent.delivery.failed` once per distinct error). The event is sent before the status is written: if the Core cannot record it the binding stays "not yet recorded" and the next pass reports it again (at-least-once, so a lost reply can leave a duplicate). Nothing per pod.
- Variables are shown in clear in the API and the audit stores only their hash ([POLICY.md](POLICY.md) "Variables"); put credentials in secrets, not in variables.

## Kubernetes versions

Minimum **1.31** by decision. `k8s-openapi` 0.28 (used by `kube` 4.2) offers `v1_32` as its earliest feature, so the Operator is built against `v1_32`. It only uses `ConfigMap`, `Secret` and workload objects unchanged since 1.31; this is inference and has to be verified on a 1.31 cluster.

## Tests

- `crates/delbert-operator`: 11 unit tests: rendering (sensitive values never in the ConfigMap, key rules, keyed hash independent of the version), identity round trip through the Secret and refusal of incomplete ones, opening sensitive values (a value for someone else fails the bundle), pod-template hash and rollout patch.
- `crates/delbert-core/tests/deliveries.rs`: administration, layered variables, file, secret sealed to the Operator only (another agent cannot open it), authorization (other identity, wrong key, no proof), refusal of incomplete bundles, delete.
