//! Delbert Core Server library.
//!
//! The Core never executes commands on managed systems: it stores, validates,
//! compiles and signs desired state; only agents act (docs/ABSTRACT.md §3).

pub mod api;
pub mod approval;
pub mod artifacts;
pub mod audit;
pub mod blobs;
pub mod audit_api;
pub mod auth;
pub mod openapi;
pub mod proxies;
pub mod totp;
pub mod secrets;
pub mod bus;
pub mod bus_auth;
pub mod config;
pub mod compile;
pub mod enroll;
