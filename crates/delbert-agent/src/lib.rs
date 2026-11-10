//! Delbert Agent engine: turns resources into `check` / `apply` on the local host.
//!
//! The agent is the only component allowed to act on a system. Every verb
//! implements [`verbs::Verb`]: `check` has no side effects, `apply` runs only
//! when `check` found drift, and the result is verified by checking again.

pub mod accounts;
pub mod containers;
pub mod cron;
pub mod daemon;
pub mod engine;
pub mod events;
pub mod facts;
pub mod fsutil;
pub mod identity;
pub mod orphans;
pub mod remediation;
pub mod runner;
pub mod system;
pub mod state;
pub mod verbs;
#[cfg(windows)]
pub mod winsvc;

pub use engine::{Ctx, Mode, Report, ResourceReport, Status, run};
