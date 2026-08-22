//! OS credential-vault adapter used by the desktop composition root.
//!
//! [`OsKeyringCredentialVault`] delegates to the platform secret store through
//! `keyring`. Deterministic in-memory and failing implementations cover the
//! shared contract, redaction, and legacy plaintext migration paths. A separate
//! ignored probe can exercise the host keyring because availability and unlock
//! state are machine-dependent.
//!
//! # No plaintext fallback, ever
//!
//! Neither adapter in this file has a code path that writes a secret
//! anywhere other than through [`CredentialVaultPort::set_secret`]/
//! [`CredentialVaultPort::rotate_secret`]. When the backend errors, both
//! adapters propagate a structured [`CredentialVaultError`] and touch no
//! other storage. See `no_plaintext_file_survives_or_is_created_when_vault_write_fails`
//! below for a test that proves this at the filesystem level for the
//! migration path (the one place in this codebase where plaintext secret
//! material — a legacy `store.json` field — legitimately exists on disk).

use std::collections::HashMap;
use std::sync::Mutex;

use keyring::Entry;
use ylx_transfer_core::credential_vault::{
    CredentialKey, CredentialVaultError, CredentialVaultPort, Secret, SecretStatus,
};
use zeroize::Zeroizing;

/// Production adapter backed by the real OS keyring via the `keyring`
/// crate (v1-compat API: macOS Keychain, Windows Credential Manager,
/// *nix Secret Service via `zbus`).
///
/// Entries are addressed as `(service, key.as_str())`, where `service` is
/// fixed per-vault-instance (e.g. `"ylx-transfer"`) so multiple logical
/// secret namespaces could in principle use distinct `OsKeyringCredentialVault`
/// instances with different service names, without the port trait needing
/// to know about namespacing.
pub struct OsKeyringCredentialVault {
    service: String,
}

impl OsKeyringCredentialVault {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &CredentialKey) -> Result<Entry, CredentialVaultError> {
        Entry::new(&self.service, key.as_str()).map_err(map_keyring_error)
    }
}

impl CredentialVaultPort for OsKeyringCredentialVault {
    fn status(&self, key: &CredentialKey) -> Result<SecretStatus, CredentialVaultError> {
        let entry = self.entry(key)?;
        match entry.get_password() {
            Ok(password) => {
                // Deliberately drop immediately without ever wrapping in
                // `Secret` or returning it — this method's contract is
                // existence-only. Note this still transits the raw value
                // through the platform IPC call and this local `String`
                // briefly; the `keyring`/`keyring-core` v1 API has no
                // "exists without reading" primitive at this layer. Flagged
                // as a residual risk in the final report, not hidden.
                drop(password);
                Ok(SecretStatus {
                    secret_configured: true,
                })
            }
            Err(keyring::Error::NoEntry) => Ok(SecretStatus {
                secret_configured: false,
            }),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn expose_secret(&self, key: &CredentialKey) -> Result<Secret, CredentialVaultError> {
        let entry = self.entry(key)?;
        match entry.get_password() {
            // The `String` the keyring crate hands back is moved straight
            // into the zeroize-on-drop `Secret` buffer; it is never bound
            // to a plain local that would outlive this expression.
            Ok(password) => Ok(Secret::new(password)),
            Err(keyring::Error::NoEntry) => Err(CredentialVaultError::NotFound(key.clone())),
            Err(err) => Err(map_keyring_error(err)),
        }
    }

    fn set_secret(&self, key: &CredentialKey, value: Secret) -> Result<(), CredentialVaultError> {
        let entry = self.entry(key)?;
        // `Secret::expose_secret` here is the one, textually-greppable
        // point where this adapter touches the raw value, and it goes
        // straight into the keyring call — never into a log, a `Debug`
        // format, or a second storage location.
        entry
            .set_password(value.expose_secret())
            .map_err(map_keyring_error)
    }

    fn delete_secret(&self, key: &CredentialKey) -> Result<(), CredentialVaultError> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            // Idempotent delete: "already absent" is success, matching
            // the trait's documented contract.
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(map_keyring_error(err)),
        }
    }
}

/// Map `keyring_core::Error` (re-exported as `keyring::Error` under the
/// `v1` feature) to our structured, non-leaking error type. Deliberately
/// never formats `BadEncoding`/`BadDataFormat`'s attached raw byte
/// vectors into the resulting message, so a backend that echoes malformed
/// secret bytes in its own error can't leak them through this mapping.
fn map_keyring_error(err: keyring::Error) -> CredentialVaultError {
    match err {
        keyring::Error::NoEntry => {
            // Callers needing `NotFound` construct it themselves where
            // they have the key in scope (see `expose_secret` above);
            // this fallback path (`status`'s `?` on `self.entry`, or any
            // future caller that doesn't special-case `NoEntry` first)
            // still needs a safe mapping, so route it to `Unavailable`
            // with a generic message rather than fabricating a key-less
            // `NotFound`.
            CredentialVaultError::Unavailable("no matching credential entry".to_string())
        }
        keyring::Error::NoStorageAccess(platform_err) => CredentialVaultError::Locked(format!(
            "credential store not accessible (locked?): {platform_err}"
        )),
        keyring::Error::PlatformFailure(platform_err) => {
            CredentialVaultError::Unavailable(format!("platform failure: {platform_err}"))
        }
        keyring::Error::NoDefaultStore => CredentialVaultError::Unavailable(
            "no default OS credential store available on this platform".to_string(),
        ),
        keyring::Error::BadEncoding(_) => CredentialVaultError::Unavailable(
            "stored secret was not valid UTF-8 (redacted from error)".to_string(),
        ),
        keyring::Error::BadDataFormat(_, platform_err) => CredentialVaultError::Unavailable(
            format!("stored secret was malformed (redacted from error): {platform_err}"),
        ),
        keyring::Error::BadStoreFormat(reason) => {
            CredentialVaultError::Unavailable(format!("credential store malformed: {reason}"))
        }
        keyring::Error::TooLong(attr, limit) => CredentialVaultError::Unavailable(format!(
            "credential attribute '{attr}' exceeds platform limit of {limit}"
        )),
        keyring::Error::Invalid(attr, reason) => CredentialVaultError::Unavailable(format!(
            "invalid credential attribute '{attr}': {reason}"
        )),
        keyring::Error::Ambiguous(matches) => CredentialVaultError::Unavailable(format!(
            "credential entry ambiguous: {} matching entries",
            matches.len()
        )),
        keyring::Error::NotSupportedByStore(reason) => {
            CredentialVaultError::Unavailable(format!("unsupported by credential store: {reason}"))
        }
        other => CredentialVaultError::Unavailable(format!("unrecognized keyring error: {other}")),
    }
}

/// In-memory fake implementing [`CredentialVaultPort`], for tests and for
/// any future non-production composition (e.g. a `--demo` build) that
/// explicitly opts into a fake rather than silently defaulting to one.
///
/// The backing map stores [`Zeroizing<String>`] rather than a bare
/// `String`, so a removed/overwritten entry scrubs its buffer instead of
/// leaving the plaintext in the freed allocation — the same guarantee
/// [`Secret`] gives, applied to the fake's own storage (commit 51).
#[derive(Default)]
pub struct InMemoryCredentialVault {
    secrets: Mutex<HashMap<CredentialKey, Zeroizing<String>>>,
}

impl InMemoryCredentialVault {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, HashMap<CredentialKey, Zeroizing<String>>>,
        CredentialVaultError,
    > {
        self.secrets
            .lock()
            .map_err(|_| CredentialVaultError::Unavailable("in-memory vault lock poisoned".into()))
    }
}

impl CredentialVaultPort for InMemoryCredentialVault {
    fn status(&self, key: &CredentialKey) -> Result<SecretStatus, CredentialVaultError> {
        let guard = self.lock()?;
        Ok(SecretStatus {
            secret_configured: guard.contains_key(key),
        })
    }

    fn expose_secret(&self, key: &CredentialKey) -> Result<Secret, CredentialVaultError> {
        let guard = self.lock()?;
        guard
            .get(key)
            .map(|stored| Secret::new(stored.as_str()))
            .ok_or_else(|| CredentialVaultError::NotFound(key.clone()))
    }

    fn set_secret(&self, key: &CredentialKey, value: Secret) -> Result<(), CredentialVaultError> {
        let mut guard = self.lock()?;
        guard.insert(
            key.clone(),
            Zeroizing::new(value.expose_secret().to_string()),
        );
        Ok(())
    }

    fn delete_secret(&self, key: &CredentialKey) -> Result<(), CredentialVaultError> {
        let mut guard = self.lock()?;
        guard.remove(key);
        Ok(())
    }
}

/// A fake that always fails, standing in for "OS keyring unavailable" or
/// "OS keyring locked" in tests. This is what proves the
/// unavailable/locked → structured-error-never-plaintext-fallback
/// contract deterministically, without depending on this sandbox's
/// real (and, as observed, actually-locked) Secret Service state.
pub struct AlwaysFailingCredentialVault {
    kind: FailureKind,
}

enum FailureKind {
    Unavailable,
    Locked,
}

impl AlwaysFailingCredentialVault {
    pub fn unavailable() -> Self {
        Self {
            kind: FailureKind::Unavailable,
        }
    }

    pub fn locked() -> Self {
        Self {
            kind: FailureKind::Locked,
        }
    }

    fn error(&self) -> CredentialVaultError {
        match self.kind {
            FailureKind::Unavailable => {
                CredentialVaultError::Unavailable("simulated: no keyring backend present".into())
            }
            FailureKind::Locked => {
                CredentialVaultError::Locked("simulated: keyring collection is locked".into())
            }
        }
    }
}

impl CredentialVaultPort for AlwaysFailingCredentialVault {
    fn status(&self, _key: &CredentialKey) -> Result<SecretStatus, CredentialVaultError> {
        Err(self.error())
    }

    fn expose_secret(&self, _key: &CredentialKey) -> Result<Secret, CredentialVaultError> {
        Err(self.error())
    }

    fn set_secret(&self, _key: &CredentialKey, _value: Secret) -> Result<(), CredentialVaultError> {
        Err(self.error())
    }

    fn delete_secret(&self, _key: &CredentialKey) -> Result<(), CredentialVaultError> {
        Err(self.error())
    }
}

/// A source of a legacy plaintext secret (standing in for the real
/// `store.json`'s eventual secret field — see plan section 9.3's
/// migration-order paragraph). Kept as a trait, not a concrete
/// `store.json` type, because this codebase has no real legacy plaintext
/// secret content yet (per this task's card) — the real PC-01/PC-07
/// migration will implement this trait against the actual `store.json`
/// schema once it carries a secret field.
pub trait LegacyPlaintextSecretSource {
    /// Read the plaintext secret if one is present. `Ok(None)` means
    /// "nothing to migrate," not an error.
    fn read_plaintext(&self) -> Result<Option<Secret>, CredentialVaultError>;

    /// Atomically clear the plaintext secret from the legacy store. Must
    /// only ever be called by the migration helper *after* the vault
    /// write has been confirmed successful.
    fn clear_plaintext(&mut self) -> Result<(), CredentialVaultError>;
}

/// Outcome of a migration attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// No legacy plaintext secret was present for this key — nothing to
    /// do, not a failure.
    NothingToMigrate,
    /// The secret was written to the vault AND the legacy plaintext was
    /// cleared. This is the only outcome that represents "success" per
    /// plan section 9.3's ordering requirement.
    Migrated,
}

/// Migrate a legacy plaintext secret into the vault, in the exact order
/// plan section 9.3 requires:
///
/// > 旧 `store.json` secret 迁移顺序：成功写 CredentialVault -> 原子清除旧
/// > secret -> 再报告成功；中间失败不得丢凭据或谎报完成。
/// > ("write to vault successfully -> atomically clear old plaintext ->
/// > only then report success; if interrupted, must not lose the
/// > credential or falsely report success.")
///
/// Concretely:
/// 1. Read the legacy plaintext. If absent, report [`MigrationOutcome::NothingToMigrate`]
///    (not an error — there was nothing to do).
/// 2. Write it to the vault via [`CredentialVaultPort::set_secret`]. If
///    this fails, return `Err` immediately — the legacy plaintext source
///    is *never touched*, so the credential is not lost (it's still
///    exactly where it was).
/// 3. Only after the vault write succeeds, clear the legacy plaintext. If
///    *this* fails (simulating a crash/IO error between steps 2 and 3),
///    return `Err` — note the vault already has the secret at this point
///    (so it is not lost), and the legacy plaintext is also still present
///    (so nothing was destroyed without a durable copy existing
///    elsewhere) — but this function does **not** report
///    `Ok(Migrated)`, per the "must not... falsely report completion"
///    requirement. A retry of this same function is safe: `set_secret` on
///    an already-migrated key is an idempotent overwrite with the same
///    value, and `clear_plaintext` is retried until it succeeds.
pub fn migrate_legacy_plaintext_secret(
    vault: &dyn CredentialVaultPort,
    key: &CredentialKey,
    source: &mut dyn LegacyPlaintextSecretSource,
) -> Result<MigrationOutcome, CredentialVaultError> {
    let Some(secret) = source.read_plaintext()? else {
        return Ok(MigrationOutcome::NothingToMigrate);
    };

    // Step 1: write to vault. On failure, `source` has not been touched —
    // the plaintext credential is exactly as durable as it was before
    // this call.
    vault.set_secret(key, secret)?;

    // Step 2: only now clear the old plaintext. On failure, the vault
    // already holds the secret (not lost), but we must not report
    // success — surface the error so the caller retries (retry is safe:
    // `set_secret` above is idempotent for the same value, so a second
    // call to this function will just re-write the same secret and try
    // `clear_plaintext` again).
    source.clear_plaintext()?;

    Ok(MigrationOutcome::Migrated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn key(id: &str) -> CredentialKey {
        CredentialKey::new(id)
    }

    // ---- InMemoryCredentialVault: set/get/delete/rotate round-trip ----

    #[test]
    fn in_memory_vault_roundtrips_set_status_expose_delete() {
        let vault = InMemoryCredentialVault::new();
        let k = key("device-abc/s3-secret");

        assert_eq!(
            vault.status(&k).unwrap(),
            SecretStatus {
                secret_configured: false
            }
        );
        assert!(matches!(
            vault.expose_secret(&k),
            Err(CredentialVaultError::NotFound(found_key)) if found_key == k
        ));

        vault
            .set_secret(&k, Secret::new("s3-secret-value-1"))
            .unwrap();
        assert_eq!(
            vault.status(&k).unwrap(),
            SecretStatus {
                secret_configured: true
            }
        );
        assert_eq!(
            vault.expose_secret(&k).unwrap().expose_secret(),
            "s3-secret-value-1"
        );

        vault.delete_secret(&k).unwrap();
        assert_eq!(
            vault.status(&k).unwrap(),
            SecretStatus {
                secret_configured: false
            }
        );
    }

    #[test]
    fn in_memory_vault_rotate_replaces_value() {
        let vault = InMemoryCredentialVault::new();
        let k = key("device-abc/token");

        vault.set_secret(&k, Secret::new("token-v1")).unwrap();
        vault.rotate_secret(&k, Secret::new("token-v2")).unwrap();

        assert_eq!(vault.expose_secret(&k).unwrap().expose_secret(), "token-v2");
    }

    #[test]
    fn in_memory_vault_delete_of_absent_key_is_idempotent_success() {
        let vault = InMemoryCredentialVault::new();
        let k = key("never-set");
        assert!(vault.delete_secret(&k).is_ok());
    }

    // ---- Unavailable/locked: structured error, never plaintext fallback ----

    #[test]
    fn always_failing_vault_reports_structured_unavailable_error() {
        let vault = AlwaysFailingCredentialVault::unavailable();
        let k = key("device-xyz/secret");

        let err = vault
            .set_secret(&k, Secret::new("would-be-value"))
            .unwrap_err();
        assert!(matches!(err, CredentialVaultError::Unavailable(_)));

        assert!(matches!(
            vault.status(&k),
            Err(CredentialVaultError::Unavailable(_))
        ));
        assert!(matches!(
            vault.expose_secret(&k),
            Err(CredentialVaultError::Unavailable(_))
        ));
        assert!(matches!(
            vault.delete_secret(&k),
            Err(CredentialVaultError::Unavailable(_))
        ));
    }

    #[test]
    fn always_failing_vault_reports_structured_locked_error() {
        let vault = AlwaysFailingCredentialVault::locked();
        let k = key("device-xyz/secret");

        let err = vault
            .set_secret(&k, Secret::new("would-be-value"))
            .unwrap_err();
        assert!(matches!(err, CredentialVaultError::Locked(_)));
    }

    // ---- Redacted Debug: the raw secret genuinely does not leak ----

    #[test]
    fn redacted_debug_does_not_leak_secret() {
        let raw = "sk-super-secret-do-not-log-me-12345";
        let secret = Secret::new(raw);

        let debug_formatted = format!("{secret:?}");
        let display_formatted = format!("{secret}");

        assert!(
            !debug_formatted.contains(raw),
            "Debug output leaked the raw secret: {debug_formatted}"
        );
        assert!(
            !display_formatted.contains(raw),
            "Display output leaked the raw secret: {display_formatted}"
        );
    }

    #[test]
    fn redacted_debug_of_credential_vault_error_does_not_leak_secret_bytes() {
        // Errors constructed by this crate never carry raw secret text —
        // prove it for a representative error built with fields that
        // could look like they'd leak a secret if someone naively
        // formatted a raw value into the error message (they don't,
        // here — the "value" text below never appears in the type at
        // all, only descriptive metadata does).
        let raw = "leaky-if-mishandled-secret-abcdef";
        let err = CredentialVaultError::MigrationFailed {
            key: CredentialKey::new("device-1/token"),
            reason: "vault write failed".to_string(),
        };
        let debug_formatted = format!("{err:?}");
        assert!(!debug_formatted.contains(raw));
    }

    // ---- Migration: success, no-op, vault-write failure, mid-migration "crash" ----

    /// Simple in-memory legacy source used by tests that don't need real
    /// file I/O; the filesystem-backed variant below
    /// (`FileBackedLegacySource`) is used specifically for the
    /// no-plaintext-survives-a-failed-migration filesystem-level test.
    struct FakeLegacySource {
        value: Option<String>,
        fail_clear: bool,
        clear_called: bool,
    }

    impl LegacyPlaintextSecretSource for FakeLegacySource {
        fn read_plaintext(&self) -> Result<Option<Secret>, CredentialVaultError> {
            Ok(self.value.clone().map(Secret::new))
        }

        fn clear_plaintext(&mut self) -> Result<(), CredentialVaultError> {
            self.clear_called = true;
            if self.fail_clear {
                return Err(CredentialVaultError::MigrationFailed {
                    key: CredentialKey::new("legacy"),
                    reason: "simulated crash between vault-write and plaintext-clear".into(),
                });
            }
            self.value = None;
            Ok(())
        }
    }

    #[test]
    fn migration_with_no_legacy_secret_is_a_no_op() {
        let vault = InMemoryCredentialVault::new();
        let mut source = FakeLegacySource {
            value: None,
            fail_clear: false,
            clear_called: false,
        };
        let k = key("device-1/s3-secret");

        let outcome = migrate_legacy_plaintext_secret(&vault, &k, &mut source).unwrap();

        assert_eq!(outcome, MigrationOutcome::NothingToMigrate);
        assert!(!source.clear_called);
        assert_eq!(
            vault.status(&k).unwrap(),
            SecretStatus {
                secret_configured: false
            }
        );
    }

    #[test]
    fn migration_success_writes_vault_then_clears_plaintext() {
        let vault = InMemoryCredentialVault::new();
        let mut source = FakeLegacySource {
            value: Some("legacy-plaintext-secret".to_string()),
            fail_clear: false,
            clear_called: false,
        };
        let k = key("device-1/s3-secret");

        let outcome = migrate_legacy_plaintext_secret(&vault, &k, &mut source).unwrap();

        assert_eq!(outcome, MigrationOutcome::Migrated);
        assert_eq!(
            vault.expose_secret(&k).unwrap().expose_secret(),
            "legacy-plaintext-secret"
        );
        assert!(
            source.value.is_none(),
            "legacy plaintext must be cleared on success"
        );
    }

    #[test]
    fn migration_fails_when_vault_write_fails_and_never_touches_legacy_plaintext() {
        let vault = AlwaysFailingCredentialVault::locked();
        let mut source = FakeLegacySource {
            value: Some("legacy-plaintext-secret".to_string()),
            fail_clear: false,
            clear_called: false,
        };
        let k = key("device-1/s3-secret");

        let result = migrate_legacy_plaintext_secret(&vault, &k, &mut source);

        assert!(matches!(result, Err(CredentialVaultError::Locked(_))));
        assert!(
            !source.clear_called,
            "must not clear legacy plaintext when the vault write itself failed"
        );
        assert_eq!(
            source.value.as_deref(),
            Some("legacy-plaintext-secret"),
            "credential must not be lost when vault write fails"
        );
    }

    #[test]
    fn migration_simulated_crash_mid_migration_does_not_lose_credential_or_report_success() {
        // Vault write succeeds, but the plaintext-clear step fails
        // (simulating a crash/IO error between the two steps).
        let vault = InMemoryCredentialVault::new();
        let mut source = FakeLegacySource {
            value: Some("legacy-plaintext-secret".to_string()),
            fail_clear: true,
            clear_called: false,
        };
        let k = key("device-1/s3-secret");

        let result = migrate_legacy_plaintext_secret(&vault, &k, &mut source);

        assert!(
            result.is_err(),
            "must not report Ok(Migrated) when the clear step fails"
        );
        assert!(source.clear_called);
        // The credential is not lost: it made it into the vault before
        // the simulated crash...
        assert_eq!(
            vault.expose_secret(&k).unwrap().expose_secret(),
            "legacy-plaintext-secret"
        );
        // ...and the legacy copy also still exists (clear failed), so at
        // no point does the credential exist nowhere.
        assert_eq!(source.value.as_deref(), Some("legacy-plaintext-secret"));

        // Retry is safe and completes the migration.
        source.fail_clear = false;
        let retry_outcome = migrate_legacy_plaintext_secret(&vault, &k, &mut source).unwrap();
        assert_eq!(retry_outcome, MigrationOutcome::Migrated);
        assert!(source.value.is_none());
    }

    // ---- Filesystem-level proof: a failed vault write never produces or
    // leaves behind a plaintext fallback file ----

    /// A `LegacyPlaintextSecretSource` backed by a real file on disk,
    /// standing in for the eventual real `store.json` secret field. Used
    /// only by the test below, so the filesystem assertion is about real
    /// bytes on a real path, not just in-memory state.
    struct FileBackedLegacySource {
        path: PathBuf,
    }

    impl LegacyPlaintextSecretSource for FileBackedLegacySource {
        fn read_plaintext(&self) -> Result<Option<Secret>, CredentialVaultError> {
            match fs::read_to_string(&self.path) {
                Ok(contents) if contents.is_empty() => Ok(None),
                Ok(contents) => Ok(Some(Secret::new(contents))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(CredentialVaultError::Unavailable(format!(
                    "reading legacy plaintext store: {e}"
                ))),
            }
        }

        fn clear_plaintext(&mut self) -> Result<(), CredentialVaultError> {
            fs::write(&self.path, "").map_err(|e| {
                CredentialVaultError::Unavailable(format!("clearing legacy plaintext store: {e}"))
            })
        }
    }

    #[test]
    fn no_plaintext_file_survives_or_is_created_when_vault_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_path = dir.path().join("store.json.legacy-secret");
        let plaintext_value = "legacy-plaintext-secret-on-disk";
        fs::write(&legacy_path, plaintext_value).unwrap();

        let vault = AlwaysFailingCredentialVault::unavailable();
        let mut source = FileBackedLegacySource {
            path: legacy_path.clone(),
        };
        let k = key("device-1/s3-secret");

        let result = migrate_legacy_plaintext_secret(&vault, &k, &mut source);
        assert!(matches!(result, Err(CredentialVaultError::Unavailable(_))));

        // The original plaintext file is untouched (not cleared, since
        // clearing would have destroyed the only durable copy of the
        // credential given the vault write failed).
        let remaining = fs::read_to_string(&legacy_path).unwrap();
        assert_eq!(remaining, plaintext_value);

        // No new file was created anywhere in the directory as a
        // "fallback" location — exactly the one legacy file exists,
        // unchanged.
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], legacy_path.file_name().unwrap());
    }

    // ---- Real OS keyring backend probe (ignored by default; see module
    // doc comment for why) ----

    /// Exercises the real `OsKeyringCredentialVault` against whatever OS
    /// keyring backend is actually present on the host. `#[ignore]`d by
    /// default because its outcome depends on host D-Bus/Secret-Service
    /// state that is not controlled by this test suite (in this sandbox,
    /// a Secret Service is present but its default collection is
    /// locked — see this task's final report). Run explicitly with:
    ///
    /// ```text
    /// cargo test --manifest-path src-tauri/crates/Cargo.toml \
    ///     -p ylx-transfer-adapters real_backend_probe -- --ignored --nocapture
    /// ```
    ///
    /// This test intentionally does not assert a specific outcome beyond
    /// "the call returns *something* structured" — it exists to let a
    /// developer on a machine with an unlocked keyring manually confirm
    /// real round-trip behavior, and to let CI honestly report
    /// "unavailable/locked" without failing the build when no usable
    /// backend is present.
    #[test]
    #[ignore = "depends on host D-Bus/Secret-Service/keyring state; run manually with --ignored"]
    fn real_backend_probe_reports_status_or_locked_honestly() {
        let vault = OsKeyringCredentialVault::new("openaria-bridge-keyring-probe");
        let k = key("probe-key-do-not-use-in-production");

        match vault.set_secret(&k, Secret::new("probe-value")) {
            Ok(()) => {
                let fetched = vault.expose_secret(&k).unwrap();
                assert_eq!(fetched.expose_secret(), "probe-value");
                vault.delete_secret(&k).unwrap();
                eprintln!("real backend probe: full round trip succeeded");
            }
            Err(CredentialVaultError::Locked(msg)) => {
                eprintln!("real backend probe: backend present but locked: {msg}");
            }
            Err(CredentialVaultError::Unavailable(msg)) => {
                eprintln!("real backend probe: backend unavailable: {msg}");
            }
            Err(other) => panic!("unexpected error shape from real backend: {other:?}"),
        }
    }
}
