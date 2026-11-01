//! Delbert Kubernetes Operator.
//!
//! The Operator is the only Delbert component that runs inside a cluster and talks to the Core.
//! Workloads get no agent and no identity of their own: configuration is delivered per
//! namespace (one `DelbertBinding` = one tenant/environment), as a `ConfigMap` and a `Secret`
//! the pods consume natively (`envFrom`, volumes). See `docs/OPERATOR.md`.
//!
//! * [`crd`]: the `DelbertBinding` custom resource.
//! * [`render`]: pure translation of a resolved bundle into the objects to apply.
//! * [`identity`]: the Operator's enrolled identity, kept in a Kubernetes `Secret`.
//! * [`core`]: fetching a bundle from the Core with the Operator's proof.
//! * [`reconcile`]: the controller loop that applies bundles and rolls out workloads.

pub mod core;
pub mod crd;
pub mod identity;
pub mod reconcile;
pub mod render;
