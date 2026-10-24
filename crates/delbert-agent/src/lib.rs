//! Delbert Agent engine: turns resources into `check` / `apply` on the local host.
//!
//! The agent is the only component allowed to act on a system. Every verb
//! implements [`verbs::Verb`]: `check` has no side effects, `apply` runs only
//! when `check` found drift, and the result is verified by checking again.

pub mod daemon;
pub mod engine;
pub mod events;
pub mod fsutil;
pub mod identity;
pub mod runner;
pub mod system;
pub mod state;
pub mod verbs;

pub use engine::{Ctx, Mode, Report, ResourceReport, Status, run};
