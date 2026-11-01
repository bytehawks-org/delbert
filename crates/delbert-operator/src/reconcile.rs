//! The controller loop: for each `DelbertBinding`, fetch the bundle from the Core, apply the
//! `ConfigMap` and the `Secret`, roll out the workloads that asked for it, write the status.
//!
//! The loop is level-triggered and idempotent: every pass computes the whole desired state and
//! applies it with server-side apply, so a drift or a missed event is repaired by the next
//! resync (`DELBERT_RESYNC_SECS`). The Core does not push to the Operator yet; polling is the
//! only trigger besides changes to the `DelbertBinding` objects themselves.

use std::{sync::Arc, time::Duration};

use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, Deployment, StatefulSet},
        core::v1::{ConfigMap, Secret},
    },
    apimachinery::pkg::apis::meta::v1::OwnerReference,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams},
    runtime::controller::Action,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    core::CoreClient,
    crd::{DelbertBinding, WorkloadKind, WorkloadRef},
    identity::Identity,
    render::{HASH_ANNOTATION, RenderError, render},
};

/// Field manager of every server-side apply.
const MANAGER: &str = "delbert-operator";
/// A binding that cannot be served by this identity is looked at again rarely.
const MISMATCH_RETRY: Duration = Duration::from_secs(600);

pub struct Context {
    pub client: Client,
    pub core: CoreClient,
    pub identity: Identity,
    pub resync: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kubernetes: {0}")]
    Kube(#[from] kube::Error),
    #[error("{0}")]
    Render(#[from] RenderError),
    #[error("{0:#}")]
    Other(#[from] anyhow::Error),
}

/// The hash currently on the pod template of a workload, if any.
pub fn template_hash(workload: &Value) -> Option<&str> {
    workload
        .pointer("/spec/template/metadata/annotations")?
        .get(HASH_ANNOTATION)?
        .as_str()
}

/// Merge patch that stamps the content hash on the pod template: a changed hash is a new pod
/// template, so Kubernetes performs its normal rolling update.
pub fn rollout_patch(hash: &str) -> Value {
    json!({ "spec": { "template": { "metadata": { "annotations": { HASH_ANNOTATION: hash } } } } })
}

/// Stamp `hash` on one workload unless it already carries it. Returns whether it was patched.
async fn roll<K>(client: &Client, ns: &str, name: &str, hash: &str) -> Result<bool, kube::Error>
where
    K: Resource<Scope = k8s_openapi::NamespaceResourceScope>
        + Clone
        + DeserializeOwned
        + Serialize
        + std::fmt::Debug,
    K::DynamicType: Default,
{
    let api: Api<K> = Api::namespaced(client.clone(), ns);
    let current = serde_json::to_value(api.get(name).await?).unwrap_or(Value::Null);
    if template_hash(&current) == Some(hash) {
        return Ok(false);
    }
    api.patch(
        name,
        &PatchParams::default(),
        &Patch::Merge(rollout_patch(hash)),
    )
    .await?;
    Ok(true)
}

async fn roll_workload(
    client: &Client,
    ns: &str,
    w: &WorkloadRef,
    hash: &str,
) -> Result<bool, kube::Error> {
    match w.kind {
        WorkloadKind::Deployment => roll::<Deployment>(client, ns, &w.name, hash).await,
        WorkloadKind::StatefulSet => roll::<StatefulSet>(client, ns, &w.name, hash).await,
        WorkloadKind::DaemonSet => roll::<DaemonSet>(client, ns, &w.name, hash).await,
    }
}

async fn set_status(
    client: &Client,
    ns: &str,
    name: &str,
    status: Value,
) -> Result<(), kube::Error> {
    let api: Api<DelbertBinding> = Api::namespaced(client.clone(), ns);
    api.patch_status(
        name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "status": status })),
    )
    .await?;
    Ok(())
}

pub async fn reconcile(binding: Arc<DelbertBinding>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = binding
        .namespace()
        .ok_or_else(|| anyhow::anyhow!("a DelbertBinding is namespaced"))?;
    let name = binding.name_any();
    let spec = &binding.spec;

    // One identity serves one tenant. Say so on the object instead of failing in a loop.
    if spec.tenant != ctx.identity.tenant {
        let msg = format!(
            "tenant '{}' is not served by this Operator (enrolled in '{}')",
            spec.tenant, ctx.identity.tenant
        );
        set_status(&ctx.client, &ns, &name, json!({ "message": msg })).await?;
        return Ok(Action::requeue(MISMATCH_RETRY));
    }

    let applied: Result<_, Error> = async {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        let bundle = ctx
            .core
            .fetch(&ctx.identity, &spec.environment, now)
            .await?
            .open(&ctx.identity.age)?;
        let mut rendered = render(spec, &bundle, &ctx.identity.hash_key)?;

        // The objects belong to the binding: deleting it removes them (garbage collection).
        let owner: Option<OwnerReference> = binding.controller_owner_ref(&());
        rendered.config_map.metadata.owner_references = owner.clone().map(|o| vec![o]);
        rendered.secret.metadata.owner_references = owner.map(|o| vec![o]);

        let apply = PatchParams::apply(MANAGER).force();
        Api::<ConfigMap>::namespaced(ctx.client.clone(), &ns)
            .patch(
                spec.config_map_name(),
                &apply,
                &Patch::Apply(&rendered.config_map),
            )
            .await?;
        Api::<Secret>::namespaced(ctx.client.clone(), &ns)
            .patch(spec.secret_name(), &apply, &Patch::Apply(&rendered.secret))
            .await?;

        let mut restarted = Vec::new();
        for w in &spec.restart_workloads {
            // A workload that does not exist (yet) is reported, not fatal: the objects are in place.
            match roll_workload(&ctx.client, &ns, w, &rendered.content_hash).await {
                Ok(true) => restarted.push(w.name.clone()),
                Ok(false) => {}
                Err(kube::Error::Api(e)) if e.code == 404 => {
                    tracing::warn!(%ns, workload = %w.name, "workload not found")
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Audit: one event per change of content, not per resync. It goes out before the status is
        // written, so a Core that cannot take it keeps the binding "not yet recorded" and the next
        // pass (idempotent) reports it again.
        let known = binding
            .status
            .as_ref()
            .and_then(|s| s.content_hash.as_deref());
        if known != Some(rendered.content_hash.as_str()) {
            let detail = format!(
                "environment '{}' version {} applied{}",
                spec.environment,
                bundle.version,
                if restarted.is_empty() {
                    String::new()
                } else {
                    format!("; restarted {}", restarted.join(", "))
                }
            );
            ctx.core
                .report(
                    &ctx.identity,
                    "delivery.applied",
                    &format!("{ns}/{name}"),
                    Some(bundle.version),
                    &detail,
                    now,
                )
                .await?;
        }
        Ok((bundle.version, rendered.content_hash, restarted))
    }
    .await;

    match applied {
        Ok((version, hash, restarted)) => {
            if !restarted.is_empty() {
                tracing::info!(%ns, binding = %name, ?restarted, "rolled out");
            }
            set_status(
                &ctx.client,
                &ns,
                &name,
                json!({ "observedVersion": version, "contentHash": hash, "message": "applied" }),
            )
            .await?;
            Ok(Action::requeue(ctx.resync))
        }
        Err(e) => {
            // Keep the last applied state in the status: only the message changes. A refusal is
            // audited once per distinct message, not at every retry.
            let message = e.to_string();
            let seen = binding.status.as_ref().and_then(|s| s.message.as_deref())
                == Some(message.as_str());
            if !seen {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                let _ = ctx
                    .core
                    .report(
                        &ctx.identity,
                        "delivery.failed",
                        &format!("{ns}/{name}"),
                        None,
                        &message,
                        now,
                    )
                    .await;
            }
            let _ = set_status(&ctx.client, &ns, &name, json!({ "message": e.to_string() })).await;
            Err(e)
        }
    }
}

pub fn error_policy(_binding: Arc<DelbertBinding>, error: &Error, ctx: Arc<Context>) -> Action {
    tracing::warn!("reconcile failed: {error}");
    Action::requeue(ctx.resync)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_read_from_the_pod_template_only() {
        let with = json!({ "metadata": { "annotations": { HASH_ANNOTATION: "meta" } }, "spec": { "template": { "metadata": { "annotations": { HASH_ANNOTATION: "abc" } } } } });
        assert_eq!(template_hash(&with), Some("abc"));
        assert_eq!(
            template_hash(&json!({ "spec": { "template": { "metadata": {} } } })),
            None
        );
        assert_eq!(template_hash(&Value::Null), None);
    }

    #[test]
    fn the_rollout_patch_touches_nothing_but_the_template_annotation() {
        let patch = rollout_patch("h1");
        assert_eq!(
            patch,
            json!({ "spec": { "template": { "metadata": { "annotations": { "delbert.bytehawks.io/content-hash": "h1" } } } } })
        );
        // Applying it on a workload that already has the hash is a no-op for `template_hash`.
        assert_eq!(template_hash(&patch), Some("h1"));
    }
}
