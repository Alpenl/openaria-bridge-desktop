//! Durable orchestration between media import, derivation, and object upload.
//!
//! This module deliberately owns only cross-job dependencies and policy. The
//! import and derivation aggregates remain authoritative for their own state,
//! while the object-store port remains authoritative for multipart completion
//! and byte verification.

mod admission;
mod pipeline;
mod projection;
mod upload_bundle;

pub use admission::*;
pub use pipeline::*;
pub use projection::*;
pub use upload_bundle::*;
