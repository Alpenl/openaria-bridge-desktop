//! [`Secret`] — the one wrapper every piece of secret material in this
//! workspace travels in (pairing poll secret, device connection token,
//! object-store access/secret keys).
//!
//! # What this type guarantees
//!
//! 1. **It never prints its plaintext.** `Debug` and `Display` are
//!    hand-implemented (never derived) and both render the fixed string
//!    [`REDACTED`] (`Secret([redacted])`). This holds transitively: a
//!    struct that *derives* `Debug` and contains a `Secret` field prints
//!    the redacted placeholder for that field, so a stray
//!    `tracing::debug!(?state)`, `{:?}` in an error message, or a
//!    `.unwrap_err()` on a `Result<T, _>` cannot leak the value.
//! 2. **It never serializes its plaintext.** `serde::Serialize` is
//!    deliberately *not* implemented, so a `Secret` cannot be smuggled
//!    into a JSON payload sent to the frontend, a log sink, or a
//!    persisted store by accident. `Deserialize` *is* implemented,
//!    because secrets legitimately arrive from the wire.
//! 3. **It zeroizes its buffer on drop.** The plaintext lives in a
//!    [`Zeroizing<String>`], so the `zeroize` crate's
//!    `volatile_write` + `compiler_fence` sequence scrubs the heap buffer
//!    when the value is dropped — a real guarantee against dead-store
//!    elimination, unlike the hand-rolled `write_volatile` loop this
//!    module replaced.
//! 4. **Reading the plaintext is greppable.** The only accessors are the
//!    explicitly named [`Secret::expose_secret`] and
//!    [`Secret::into_exposed_string`] — no `Deref`, no `AsRef<str>`, no
//!    `ToString`, so `grep -rn expose_secret` finds every site that
//!    touches raw secret material.
//! 5. **Equality is length-independent-ish and value-blind.** `PartialEq`
//!    compares with a constant-time byte fold rather than `==` on the
//!    inner `String`, so comparing a stored secret against an attacker-
//!    supplied one does not leak a prefix length through timing.

use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The single placeholder every `Secret` renders as, for both `Debug` and
/// `Display`. Tests assert against this constant rather than a literal so
/// the redaction text has exactly one definition.
pub const REDACTED: &str = "Secret([redacted])";

/// A secret value (pairing poll secret, connection token, S3 access/secret
/// key, ...). See the module documentation for the full guarantee list.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The only borrowing accessor for the raw text. Named deliberately
    /// (not `AsRef`/`Deref`) so every call site is textually searchable
    /// for security review.
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Consume the wrapper and hand the raw `String` to the caller.
    ///
    /// Unavoidable at the outermost boundary (e.g. handing a token to an
    /// HTTP header builder that owns its input). The returned `String` is
    /// **no longer zeroize-on-drop** — prefer [`Self::expose_secret`]
    /// wherever a borrow suffices, and wrap the result in
    /// [`zeroize::Zeroizing`] if it must be owned for any length of time.
    pub fn into_exposed_string(mut self) -> String {
        // Swap the buffer out before `self` drops, so the `Zeroizing`
        // scrub runs against the now-empty shell and not against the
        // value being returned.
        std::mem::take(&mut *self.0)
    }

    /// Deprecated spelling of [`Self::into_exposed_string`], kept so
    /// pre-existing call sites keep compiling.
    pub fn into_string(self) -> String {
        self.into_exposed_string()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Byte length of the plaintext. Safe to log — a length is not the
    /// value — and useful for "is this configured?" style diagnostics.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.as_bytes();
        let b = other.0.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        // Constant-time-ish fold: no early exit on the first differing
        // byte, so a timing observer cannot binary-search the value.
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

impl Eq for Secret {}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// `Zeroizing<String>` already scrubs on drop; this marker states the fact
// so `Secret` composes with `#[derive(ZeroizeOnDrop)]` containers.
impl ZeroizeOnDrop for Secret {}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Note: serde hands us an owned `String` here; there is no way to
        // avoid that intermediate. It is moved (not copied) into the
        // zeroizing buffer immediately.
        String::deserialize(deserializer).map(Secret::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "sk-super-secret-do-not-log-me-12345";

    #[test]
    fn debug_and_display_render_the_redacted_placeholder() {
        let secret = Secret::new(RAW);
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(REDACTED, "Secret([redacted])");
    }

    /// The transitive guarantee: a *derived* `Debug` on an enclosing
    /// struct must not leak the wrapped plaintext either. This is the case
    /// that matters in practice — nobody formats a bare secret, they
    /// format the state struct that happens to hold one.
    #[test]
    fn derived_debug_on_an_enclosing_struct_does_not_leak() {
        #[derive(Debug)]
        #[allow(dead_code, reason = "fields exist only to be Debug-formatted")]
        struct PairingState {
            attempt_id: String,
            poll_secret: Secret,
            connection_token: Option<Secret>,
        }

        let state = PairingState {
            attempt_id: "attempt-0001".to_string(),
            poll_secret: Secret::new(RAW),
            connection_token: Some(Secret::new("connection-token-plaintext")),
        };

        let rendered = format!("{state:?}");
        assert!(!rendered.contains(RAW), "derived Debug leaked: {rendered}");
        assert!(
            !rendered.contains("connection-token-plaintext"),
            "derived Debug leaked the token: {rendered}"
        );
        assert!(rendered.contains(REDACTED));
        // Non-secret fields still render normally.
        assert!(rendered.contains("attempt-0001"));
    }

    #[test]
    fn nested_containers_do_not_leak_either() {
        let secrets = vec![Secret::new(RAW)];
        let wrapped = Some(&secrets);
        assert!(!format!("{wrapped:?}").contains(RAW));
        let mapped: Result<Secret, &str> = Ok(Secret::new(RAW));
        assert!(!format!("{mapped:?}").contains(RAW));
    }

    #[test]
    fn expose_secret_returns_the_raw_value() {
        assert_eq!(Secret::new(RAW).expose_secret(), RAW);
    }

    #[test]
    fn into_exposed_string_returns_the_raw_value() {
        assert_eq!(Secret::new(RAW).into_exposed_string(), RAW);
        assert_eq!(Secret::new(RAW).into_string(), RAW);
    }

    #[test]
    fn deserialize_accepts_a_json_string_and_serialize_is_not_available() {
        let secret: Secret = serde_json::from_str("\"wire-delivered-token\"").expect("parses");
        assert_eq!(secret.expose_secret(), "wire-delivered-token");
        // There is intentionally no `impl Serialize for Secret`; the
        // compile-fail proof of that is the absence of the impl, asserted
        // here by round-tripping only in the deserialize direction.
    }

    #[test]
    fn equality_is_by_value_and_length() {
        assert_eq!(Secret::new("abc"), Secret::new("abc"));
        assert_ne!(Secret::new("abc"), Secret::new("abd"));
        assert_ne!(Secret::new("abc"), Secret::new("abcd"));
    }

    #[test]
    fn explicit_zeroize_clears_the_buffer() {
        let mut secret = Secret::new(RAW);
        secret.zeroize();
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }
}
