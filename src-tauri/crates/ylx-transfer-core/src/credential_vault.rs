//! `CredentialVaultPort` — SPIKE-PC-CRED provisional port (pre-PC-00/PC-07).
//!
//! # Status: spike, not frozen
//!
//! This module is an **explicitly authorized, out-of-sequence spike**
//! (plan section 9.3's last paragraph, section 10.1's `ADR-CRED-001` row,
//! section 6.1 invariant 13). It is **not** task PC-07. The plan normally
//! gates real PC-07 credential-vault work behind PC-00 (core scaffold/
//! ports), which is itself gated behind Wave 2's Pi API being formally
//! frozen. The coordinator approved doing this piece early because OS
//! keyring access does not need to know Pi's wire protocol at all — it
//! only needs a generic secret-storage port.
//!
//! **The real PC-00 will define the frozen port shape; the real PC-07 will
//! evaluate, adapt, or replace everything in this module.** Nothing here
//! is wired into any production Tauri command (`src-tauri/src/{lib,
//! commands}.rs`) — see `ylx-transfer-adapters::credential_keyring` for the
//! adapter that implements this trait, also marked SPIKE-level.
//!
//! `CredentialVaultPort` is the secret-vault contract for this spike. It
//! explicitly calls for: (1) a redacted secret
//! newtype that resists accidental logging, (2) a raw-secret accessor kept
//! separate from an existence-only check so callers that don't need the
//! secret value can't accidentally acquire it, and (3) rotate as a named
//! operation distinct from `set` (todo for the real port: rotate may want
//! different audit semantics, e.g. keep-previous-as-backup, so it's kept
//! as its own trait method rather than a caller-side `set` alias).
//!
//! # Design choices worth flagging for the real port review
//!
//! - **Key type**: [`CredentialKey`] wraps a `String` rather than being a
//!   bare `&str` everywhere, so call sites can't accidentally pass a raw
//!   secret where a key was expected (a `Secret` and a `CredentialKey` are
//!   different types; the compiler rejects mixing them up).
//! - **Secret newtype**: [`Secret`] never derives `Debug`/`Display`/
//!   `serde::Serialize` — it hand-implements a redacted `Debug`/`Display`
//!   so a stray `format!("{:?}", ...)` or `tracing::debug!(?value)` cannot
//!   leak the raw value (see `credential_keyring`'s
//!   `redacted_debug_does_not_leak_secret` test for proof). The raw value
//!   is reachable only through the explicitly named [`Secret::expose_secret`]
//!   method — `grep`-able and code-review-able by design.
//! - **Existence vs. value**: [`CredentialVaultPort::status`] returns only
//!   a `secret_configured: bool`-shaped [`SecretStatus`]; only
//!   [`CredentialVaultPort::expose_secret`] can produce a raw [`Secret`].
//!   This matches plan section 13's PC-07 merge gate: "getter只返回
//!   `secret_configured`".
//! - **No plaintext fallback, ever**: [`CredentialVaultError`] has no
//!   "degraded/plaintext" variant. Every error variant is a hard failure
//!   the caller must handle explicitly; there is no code path in this
//!   trait's contract that allows silently writing an unencrypted copy of
//!   a secret when the backend is unavailable or locked (plan section
//!   10.1 `ADR-CRED-001` "未决时禁止：secret 回显/明文 fallback"; section
//!   6.1 invariant 13).

use std::fmt;

/// A stable identifier for a secret in the vault (e.g. a per-device or
/// per-object-store-profile identifier). Wrapped in its own type so it
/// can never be confused with a [`Secret`] at a call site — the two types
/// are not interchangeable, so passing a raw secret where a key is
/// expected (or vice versa) is a compile error, not a runtime bug.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CredentialKey(String);

impl CredentialKey {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys are stable identifiers (device/profile ids), not secret
        // material — safe to display as-is, unlike `Secret`.
        write!(f, "{}", self.0)
    }
}

/// The secret newtype every vault operation carries values in.
///
/// Re-exported from [`crate::secret`] — commit 51 moved the definition
/// there and replaced this module's previous hand-rolled `write_volatile`
/// `Drop` scrub with the `zeroize` crate's compiler-fence-backed one, so
/// the same type is shared by the vault, the keyring adapter, and the Pi
/// HTTP client (pairing poll secret / connection token) instead of each
/// layer inventing its own wrapper. The re-export keeps every existing
/// `ylx_transfer_core::credential_vault::Secret` import working.
///
/// See [`crate::secret`]'s module documentation for the exact guarantees
/// (redacted `Debug`/`Display`, no `Serialize`, zeroize-on-drop,
/// greppable-only plaintext access).
pub use crate::secret::Secret;

/// Existence-only view of a secret — never carries the raw value.
/// This is what callers that only need "is this configured?" (e.g. a UI
/// checkbox, a "storage profile complete" check) should ask for, per
/// plan section 13's PC-07 merge gate ("getter只返回 `secret_configured`").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretStatus {
    pub secret_configured: bool,
}

/// Structured, non-leaking error type for vault operations.
///
/// No variant carries raw secret bytes. `NoEntry`/`BadEncoding`-style
/// upstream errors from a real backend are deliberately summarized rather
/// than passed through verbatim, so a backend that (say) echoes malformed
/// secret bytes in its own error message can't leak them through this
/// type.
#[derive(Debug, thiserror::Error)]
pub enum CredentialVaultError {
    /// The backend could not be reached/initialized at all (e.g. no
    /// Secret Service running, no platform credential store available).
    /// This is a hard failure — callers must **never** interpret this as
    /// "fall back to plaintext."
    #[error("credential backend unavailable: {0}")]
    Unavailable(String),
    /// The backend exists but is locked (e.g. a locked Secret Service
    /// collection) and could not be unlocked non-interactively. Also a
    /// hard failure with the same no-plaintext-fallback rule.
    #[error("credential backend locked: {0}")]
    Locked(String),
    /// No secret is stored for this key.
    #[error("no secret stored for credential '{0}'")]
    NotFound(CredentialKey),
    /// The backend rejected the operation for permission reasons.
    #[error("credential backend permission denied: {0}")]
    PermissionDenied(String),
    /// A legacy-plaintext-to-vault migration failed partway. See
    /// `credential_keyring::migrate_legacy_plaintext_secret` for the
    /// ordering guarantee this variant supports.
    #[error("credential migration failed for '{key}': {reason}")]
    MigrationFailed { key: CredentialKey, reason: String },
}

/// Port for a real secret vault (OS keyring in production).
///
/// Implementors MUST NOT fall back to plaintext storage under any error
/// condition (plan section 10.1 `ADR-CRED-001`, section 6.1 invariant 13).
/// If the backend is unavailable or locked, return
/// [`CredentialVaultError::Unavailable`]/[`CredentialVaultError::Locked`]
/// — never silently write the secret anywhere else.
pub trait CredentialVaultPort: Send + Sync {
    /// Existence-only check. Never returns raw secret material.
    fn status(&self, key: &CredentialKey) -> Result<SecretStatus, CredentialVaultError>;

    /// Raw-secret accessor for code paths that actually need the secret
    /// value (e.g. signing an S3 request). Kept as a separate, explicitly
    /// named method (not folded into `status`) so a call site that only
    /// wants to check configuration can't accidentally end up holding a
    /// [`Secret`] it didn't need.
    fn expose_secret(&self, key: &CredentialKey) -> Result<Secret, CredentialVaultError>;

    /// Store (create or overwrite) a secret.
    fn set_secret(&self, key: &CredentialKey, value: Secret) -> Result<(), CredentialVaultError>;

    /// Remove a stored secret. Deleting a key that doesn't exist is not
    /// itself an error condition callers need to special-case beyond
    /// `NotFound` if the implementation chooses to surface it that way;
    /// implementations in this spike treat "already absent" as success
    /// (idempotent delete) — see adapter doc comments for the exact
    /// per-backend behavior.
    fn delete_secret(&self, key: &CredentialKey) -> Result<(), CredentialVaultError>;

    /// Rotate (replace) a secret. Kept as a distinct named operation from
    /// `set_secret`, even though the default implementation is just a
    /// `set_secret` call, so that (a) call sites document *intent*
    /// ("this is a rotation, not an initial set") for audit purposes, and
    /// (b) a future implementation can give rotation different semantics
    /// (e.g. briefly retain the previous value for rollback) without
    /// changing the trait shape.
    fn rotate_secret(
        &self,
        key: &CredentialKey,
        new_value: Secret,
    ) -> Result<(), CredentialVaultError> {
        self.set_secret(key, new_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_and_display_are_redacted() {
        let secret = Secret::new("super-secret-token-value");
        let debug_output = format!("{secret:?}");
        let display_output = format!("{secret}");
        assert!(!debug_output.contains("super-secret-token-value"));
        assert!(!display_output.contains("super-secret-token-value"));
        assert_eq!(debug_output, "Secret([redacted])");
        assert_eq!(display_output, "Secret([redacted])");
    }

    /// A `CredentialVaultError` is routinely `{:?}`/`{}`-formatted into a
    /// log line or a Tauri command's error string. None of its variants
    /// may carry raw secret material — the only value-shaped variant
    /// carries a [`CredentialKey`], which is a plain identifier.
    #[test]
    fn vault_errors_never_embed_secret_material() {
        let key = CredentialKey::new("ylx.storage.default");
        let rendered = format!("{:?} {}", CredentialVaultError::NotFound(key.clone()), {
            CredentialVaultError::MigrationFailed {
                key,
                reason: "backend locked".to_string(),
            }
        });
        assert!(rendered.contains("ylx.storage.default"));
        assert!(!rendered.to_lowercase().contains("password"));
    }

    #[test]
    fn secret_expose_secret_returns_raw_value() {
        let secret = Secret::new("raw-value");
        assert_eq!(secret.expose_secret(), "raw-value");
    }

    #[test]
    fn credential_key_display_is_plain() {
        let key = CredentialKey::new("device-123");
        assert_eq!(format!("{key}"), "device-123");
    }
}
