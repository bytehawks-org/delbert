//! Delbert Proxy: the only component of a branch office that talks to the Core
//! (docs/ABSTRACT.md §2).
//!
//! The agents of the site connect to a NATS server and an HTTPS endpoint run next to the
//! proxy, never to the Core. The proxy:
//!
//! * authorizes them locally (NATS authorization callout) from an allow-list synchronized
//!   from the Core, so the site keeps working when the link is down;
//! * relays their policy requests and certificate renewals to the Core, answering from its
//!   cache when the Core cannot be reached;
//! * republishes the Core's notifications to its agents;
//! * queues their compliance reports (latest per agent) and forwards them when it can;
//! * relays agent enrollment and caches artifacts by hash.

pub mod allowlist;
pub mod hub;
pub mod identity;
pub mod queue;
pub mod relay;
pub mod web;
