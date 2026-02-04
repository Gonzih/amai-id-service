//! AMAI Identity Service
//!
//! Cryptographic identity layer for autonomous agents.
//! Uses Ed25519/RSA keys for authentication (Keybase-style).
//!
//! ## Architecture
//!
//! - **Identity**: Each agent has a unique identity with public key(s)
//! - **Soulchain**: Append-only cryptographic chain of all actions
//! - **Authentication**: Every API request is signed with private key
//! - **No blockchain**: Pure cryptographic identity, no on-chain transactions

pub mod api;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod error;
pub mod soulchain;
pub mod state;
pub mod types;

pub use config::Config;
pub use error::{ApiError, ApiResult};
pub use state::AppState;
