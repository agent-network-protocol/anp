//! Rust SDK entry point for Agent Network Protocol.

mod canonical_json;
pub mod direct_e2ee;
mod keys;

pub mod authentication;
pub mod proof;
pub mod wns;

pub const VERSION: &str = "0.8.5";

pub use keys::{PrivateKeyMaterial, PublicKeyMaterial};
