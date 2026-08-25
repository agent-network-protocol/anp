//! Rust SDK entry point for Agent Network Protocol.

mod canonical_json;
pub mod direct_e2ee;
pub mod group_e2ee;
mod keys;

pub mod authentication;
pub mod proof;
pub mod sealed_handoff;
pub mod wns;

pub const VERSION: &str = "1.0.0";

pub use keys::{PrivateKeyMaterial, PublicKeyMaterial};
