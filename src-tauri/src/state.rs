//! In-memory application state plus disk persistence.
//!
//! `library` and `storage` survive app restarts. Production device state,
//! authenticated sessions, download jobs, and network clients live in
//! `composition::Composition`; this store holds their UI projection, local
//! library metadata, S3 upload rows, and persisted non-secret settings.
//! The `sessions` demo fleet exists only behind the explicit `demo` feature.

#[cfg(feature = "demo")]
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ylx_transfer_core::persistence::{AppLibraryPayload, AppStore, AppStoreSnapshot};

use crate::composition::Composition;
#[cfg(feature = "demo")]
use crate::models::{Device, DownloadStatus, Session, SessionView, TransferState};
use crate::models::{LibraryEntry, PersistedStore, StorageConfig};

/// Shared managed handle for application data. Commands and background
/// workers borrow the same lock through an `Arc`; the application facade can
/// therefore own a stable reference without opening a second state model.
#[derive(Clone)]
pub struct AppState(pub Arc<Mutex<AppData>>);

pub struct AppData {
    /// Demo-only fleet, seeded from `demo::seed_devices()` and merged into
    /// `list_devices`'s output alongside the real `Composition`-backed
    /// devices -- only present when built with `--features demo` (off by
    /// default, see `Cargo.toml`).
    #[cfg(feature = "demo")]
    pub devices: Vec<Device>,
    /// Demo-only session fleet. Production sessions are read live from
    /// the authenticated Pi catalog by `composition`, never cached here.
    #[cfg(feature = "demo")]
    pub sessions: HashMap<String, Vec<Session>>,
    pub library: Vec<LibraryEntry>,
    #[cfg(feature = "demo")]
    pub demo_transfer_state: crate::sim::DemoTransferState,
    /// Process-local gate held from the delete snapshot through the durable
    /// rename/CAS. The cross-process AppStore lease is acquired after this
    /// lock is released; this set only closes same-process command races.
    pub library_delete_keys: HashSet<String>,
    pub storage: StorageConfig,
    pub notify_enabled: bool,
    /// Production composition root (device registry, pairing, transfer
    /// coordinator, local library and object-store adapters).
    pub composition: Arc<Composition>,
    /// Shared with the media composition. §8.2 of the Ubuntu pipeline
    /// specification requires one connection: a worker that opened its own
    /// would bypass this store's revision compare-and-swap entirely.
    store: Arc<AppStore>,
    /// Revision of the complete snapshot most recently loaded or committed.
    /// Every replacement is compare-and-swap guarded so an external writer
    /// cannot be silently overwritten by this process's stale in-memory copy.
    store_revision: AtomicU64,
}

#[cfg(feature = "demo")]
fn demo_download_status(
    complete_local: bool,
    states: impl IntoIterator<Item = TransferState>,
) -> DownloadStatus {
    let mut has_failed = false;
    let mut has_succeeded = false;
    for state in states {
        match state {
            TransferState::Queued
            | TransferState::Preparing
            | TransferState::Running
            | TransferState::Paused
            | TransferState::Cancelling => return DownloadStatus::Downloading,
            TransferState::Failed | TransferState::Cancelled => has_failed = true,
            TransferState::Succeeded | TransferState::Finalizing => has_succeeded = true,
        }
    }
    if complete_local || has_succeeded {
        DownloadStatus::Done
    } else if has_failed {
        DownloadStatus::Failed
    } else {
        DownloadStatus::None
    }
}

impl AppData {
    /// Borrow the durable application store for operations that need a
    /// filesystem/metadata transaction (library deletion leases and intents).
    pub fn app_store(&self) -> &AppStore {
        &self.store
    }

    /// Share the durable store with another owner.
    ///
    /// Callers must not hold the `AppData` lock while using it — outbox replay
    /// and projection commits are their own transactions and must never run
    /// underneath the application-state mutex.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn app_store_handle(&self) -> Arc<AppStore> {
        Arc::clone(&self.store)
    }

    pub fn store_revision(&self) -> u64 {
        self.store_revision.load(Ordering::Acquire)
    }

    pub fn set_store_revision(&self, revision: u64) {
        self.store_revision.store(revision, Ordering::Release);
    }

    pub fn claim_library_delete_keys(&mut self, keys: &[String]) -> Result<(), String> {
        if keys
            .iter()
            .any(|key| self.library_delete_keys.contains(key))
        {
            return Err("本地记录正在执行删除操作，请稍后重试".to_string());
        }
        self.library_delete_keys.extend(keys.iter().cloned());
        Ok(())
    }

    pub fn release_library_delete_keys(&mut self, keys: &[String]) {
        for key in keys {
            self.library_delete_keys.remove(key);
        }
    }

    #[cfg(feature = "demo")]
    pub fn download_status(&self, device_id: &str, session_id: &str) -> DownloadStatus {
        let complete_local = self.library.iter().any(|entry| {
            entry.device_id == device_id && entry.session_id == session_id && entry.complete
        });
        let states = self
            .demo_transfer_state
            .transfers()
            .iter()
            .filter_map(|transfer| {
                matches!(
                    self.demo_transfer_state.get(&transfer.key),
                    Some(crate::sim::DemoTransferContext::DownloadSession {
                        device_id: transfer_device,
                        session_id: transfer_session,
                    }) if transfer_device == device_id && transfer_session == session_id
                )
                .then_some(transfer.state)
            });
        demo_download_status(complete_local, states)
    }

    #[cfg(feature = "demo")]
    pub fn is_backed_up(&self, device_id: &str, session_id: &str) -> bool {
        self.library.iter().any(|e| {
            e.device_id == device_id
                && e.session_id == session_id
                && e.upload_status == crate::models::UploadStatus::Done
        })
    }

    #[cfg(feature = "demo")]
    pub fn session_views(&self, device_id: &str) -> Vec<SessionView> {
        self.sessions
            .get(device_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|session| {
                let download_status = self.download_status(device_id, &session.id);
                let backed_up = self.is_backed_up(device_id, &session.id);
                SessionView {
                    session,
                    download_status,
                    backed_up,
                }
            })
            .collect()
    }

    pub fn persist_result(&self) -> Result<(), String> {
        let library = self
            .library
            .iter()
            .map(|entry| {
                serde_json::to_vec(entry)
                    .map(|payload| AppLibraryPayload {
                        entry_key: entry.key(),
                        payload,
                    })
                    .map_err(|error| {
                        format!("failed to serialize library entry {}: {error}", entry.key())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let storage = serde_json::to_vec(&self.storage)
            .map_err(|error| format!("failed to serialize storage profile: {error}"))?;
        let expected_revision = self.store_revision.load(Ordering::Acquire);
        let committed_revision = self
            .store
            .save_if_revision(expected_revision, &library, &storage)
            .map_err(|error| format!("failed to commit application SQLite store: {error}"))?;
        self.store_revision
            .store(committed_revision, Ordering::Release);
        Ok(())
    }

    #[cfg(feature = "demo")]
    pub fn persist(&self) {
        if let Err(e) = self.persist_result() {
            eprintln!("[state] application store persistence failed: {e}");
        }
    }
}

/// Everything boot stage 1 ("load and migrate the persisted configuration")
/// produces, before any runtime exists.
///
/// This is the *only* read of the persisted configuration during startup.
/// It used to be read twice -- once by a `peek_download_root` helper that
/// opened the SQLite store directly to pick the initial library root, and
/// again by `AppState::new` -- which meant the very first launch after a
/// legacy `store.json` migration picked the *default* root (the SQLite
/// storage row does not exist yet at peek time) and only honoured the
/// user's configured directory from the *next* launch onwards. Loading and
/// migrating exactly once, here, means a legacy custom directory is in
/// effect during the migrating run itself.
///
/// The already-opened [`AppStore`] is carried through rather than reopened,
/// so the migration decisions taken here (is SQLite authoritative? is there
/// a legacy file to scrub and archive?) cannot be recomputed differently by
/// a second reader.
pub struct BootConfig {
    store: AppStore,
    store_revision: u64,
    store_path: PathBuf,
    legacy_store_path: PathBuf,
    /// Whether a legacy `store.json` was present on disk. The raw text is
    /// deliberately not carried: all stage 3 still needs to know is that
    /// the file has to be scrubbed and archived.
    legacy_present: bool,
    sqlite_is_authoritative: bool,
    importing_legacy: bool,
    clean_legacy_payload: Vec<u8>,
    legacy_credential: Option<(String, String)>,
    library: Vec<LibraryEntry>,
    storage: StorageConfig,
}

impl BootConfig {
    /// Boot stage 1. Reads the SQLite store, falls back to (and captures
    /// the plaintext credential of) a legacy `store.json`, and applies the
    /// shipped storage defaults -- all without constructing a runtime.
    pub fn load(store_path: PathBuf) -> Result<Self, String> {
        let legacy_store_path = store_path.with_file_name("store.json");
        let store = AppStore::open(&store_path)
            .map_err(|error| format!("failed to open application SQLite store: {error}"))?;
        let sqlite_snapshot = store
            .load()
            .map_err(|error| format!("failed to load application SQLite store: {error}"))?;
        let store_revision = sqlite_snapshot.revision;
        let sqlite_is_authoritative = store_revision > 0;
        let legacy_raw = match fs::read_to_string(&legacy_store_path) {
            Ok(raw) => Some(raw),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                    "failed to read legacy application store at {legacy_store_path:?}: {error}"
                ))
            }
        };
        // PC-06 security fix: `StorageConfig` no longer has
        // `accessKey`/`secretKey` fields (see that struct's doc comment
        // in `models.rs`), so `serde_json::from_str::<PersistedStore>`
        // below silently ignores any such fields in an old-format
        // `store.json` written by a pre-PC-06 build -- they'd simply
        // vanish on the next `persist()` without ever being migrated.
        // `extract_legacy_plaintext_credential` reads them out of the raw
        // JSON *before* that happens, so they can be moved into the
        // credential vault instead of silently discarded.
        let (persisted, legacy_credential, importing_legacy) = if sqlite_is_authoritative {
            (persisted_from_sqlite(sqlite_snapshot)?, None, false)
        } else {
            match legacy_raw.as_deref() {
                Some(raw) => (
                    serde_json::from_str::<PersistedStore>(raw).map_err(|error| {
                        format!(
                            "legacy application store at {legacy_store_path:?} is corrupt: {error}"
                        )
                    })?,
                    extract_legacy_plaintext_credential(raw),
                    true,
                ),
                None => (PersistedStore::default(), None, false),
            }
        };
        let clean_legacy_payload = serde_json::to_vec_pretty(&persisted)
            .map_err(|error| format!("failed to serialize legacy migration snapshot: {error}"))?;

        let PersistedStore {
            library,
            mut storage,
        } = persisted;
        // A store written by a build that predates the shipped defaults has
        // empty coordinates, and would otherwise pin the app to "please
        // configure storage" forever -- the built-in default only ever
        // applied to a store that did not exist at all. `save_storage_config`
        // rejects an empty endpoint/bucket, so an empty pair here can only
        // mean "never configured", never "deliberately cleared".
        if !storage.is_configured() {
            let defaults = crate::models::StorageConfig::default();
            storage.endpoint = defaults.endpoint;
            storage.bucket = defaults.bucket;
            storage.url_style = defaults.url_style;
        }

        Ok(BootConfig {
            store,
            store_revision,
            store_path,
            legacy_store_path,
            legacy_present: legacy_raw.is_some(),
            sqlite_is_authoritative,
            importing_legacy,
            clean_legacy_payload,
            legacy_credential,
            library,
            storage,
        })
    }

    /// The user's configured download directory as loaded above, or `None`
    /// to mean "use the default root". Available before the runtime is
    /// built, which is the whole point of loading the configuration first.
    pub fn download_root(&self) -> Option<PathBuf> {
        resolve_download_root(self.storage.download_root.as_deref())
    }
}

impl AppState {
    /// Builds an application state around an already-open SQLite store for
    /// composition tests. Production boot uses [`Self::from_boot_config`],
    /// which also performs migrations and startup reconciliation; tests that
    /// exercise one projection boundary need only supply the durable app
    /// store and an authoritative library snapshot.
    #[cfg(test)]
    pub(crate) fn for_test(
        composition: Arc<Composition>,
        store: Arc<AppStore>,
        library: Vec<LibraryEntry>,
        store_revision: u64,
    ) -> Self {
        #[cfg(feature = "demo")]
        let (devices, sessions) = crate::demo::seed_devices();
        Self(Arc::new(Mutex::new(AppData {
            #[cfg(feature = "demo")]
            devices,
            #[cfg(feature = "demo")]
            sessions,
            library,
            #[cfg(feature = "demo")]
            demo_transfer_state: crate::sim::DemoTransferState::default(),
            library_delete_keys: HashSet::new(),
            storage: StorageConfig::default(),
            notify_enabled: false,
            composition,
            store,
            store_revision: AtomicU64::new(store_revision),
        })))
    }

    /// Boot stage 3: turns an already-loaded [`BootConfig`] plus an inert
    /// runtime into the managed application state, performing every
    /// migration that needs the runtime (legacy credential -> vault,
    /// interrupted-upload reconciliation, legacy store scrub/archive).
    ///
    /// Deliberately takes a `BootConfig` rather than a path: the persisted
    /// configuration is read exactly once per boot, by [`BootConfig::load`].
    pub fn from_boot_config(
        boot: BootConfig,
        composition: Arc<Composition>,
    ) -> Result<Self, String> {
        let BootConfig {
            store,
            store_revision,
            store_path,
            legacy_store_path,
            legacy_present,
            sqlite_is_authoritative,
            importing_legacy,
            clean_legacy_payload,
            legacy_credential,
            mut library,
            storage,
        } = boot;

        // An upload that was in flight when the app exited left its entry
        // stuck at `UploadStatus::Uploading` forever: nothing ever emits a
        // terminal transition for a process that is gone. Reconciling here
        // -- after the library is loaded, before it becomes visible state --
        // is the only point where "still uploading" can be distinguished
        // from "was uploading in a previous life".
        let reconciled = crate::composition::reconcile_interrupted_uploads(
            &composition,
            &mut library,
            &storage,
        )?;

        // Resolve every durable local-library delete only after interrupted
        // uploads have been durably cancelled and their multipart rows have
        // been claimed. Recovery now sees terminal upload jobs and can
        // release stale upload leases without letting a crashed worker block
        // deletion or a new upload indefinitely.
        crate::library_delete::recover_pending_deletes(&store, &composition.library_root())?;
        // One shared connection from here on: the media completion projector
        // gets this same handle rather than opening a second writer.
        let store = Arc::new(store);

        #[cfg(feature = "demo")]
        let (devices, sessions) = crate::demo::seed_devices();
        let state = AppState(Arc::new(Mutex::new(AppData {
            #[cfg(feature = "demo")]
            devices,
            #[cfg(feature = "demo")]
            sessions,
            library,
            #[cfg(feature = "demo")]
            demo_transfer_state: crate::sim::DemoTransferState::default(),
            library_delete_keys: HashSet::new(),
            storage,
            notify_enabled: false,
            composition: composition.clone(),
            store,
            store_revision: AtomicU64::new(store_revision),
        })));

        if let Some((access_key, secret_key)) = legacy_credential {
            // Mirrors `credential_keyring::migrate_legacy_plaintext_secret`'s
            // ordering contract (that exact helper isn't called here since
            // it wants a `LegacyPlaintextSecretSource` tied to a single
            // string, not this struct's two fields + whole-snapshot
            // persistence): write to the vault FIRST, and only once that
            // succeeds, persist the now-secret-free snapshot (which
            // atomically clears the legacy plaintext, since the current
            // `StorageConfig` shape has nowhere to put it). If the vault
            // write fails, the legacy JSON is left completely untouched --
            // the credential is not lost, and the next launch retries.
            composition
                .set_storage_credential(access_key, secret_key)
                .map_err(|error| {
                    format!(
                        "failed to migrate legacy storage credential into the OS keyring; \
                         the original store was left untouched: {error}"
                    )
                })?;
        }

        // Strictly after the legacy migration: a credential the user really
        // entered in an older build must win over any bootstrap file. This
        // is a no-op once the vault holds anything at all.
        if let Some(app_data_dir) = store_path.parent() {
            crate::composition::bootstrap_storage_credential(&composition, app_data_dir);
        }

        if legacy_present {
            rewrite_legacy_store(&legacy_store_path, &clean_legacy_payload)?;
        }
        if !sqlite_is_authoritative {
            state.0.lock().unwrap().persist_result().map_err(|error| {
                if importing_legacy {
                    format!("failed to migrate legacy application data into SQLite: {error}")
                } else {
                    format!("failed to initialize application SQLite state: {error}")
                }
            })?;
        }
        if legacy_present {
            archive_legacy_store(&legacy_store_path)?;
        }
        // The `!sqlite_is_authoritative` branch above already wrote the
        // reconciled library, so only an authoritative store needs this
        // extra commit. A failure here aborts this boot after the durable
        // upload cancellation has already won. The next start reads the
        // unchanged library row plus the unacknowledged cancellation outbox,
        // reapplies the terminal projection, and then acknowledges it; this
        // is the explicit recoverable second-start policy rather than
        // resurrecting or blanket-cancelling the job again.
        if reconciled && sqlite_is_authoritative {
            state.0.lock().unwrap().persist_result().map_err(|error| {
                format!("无法持久化启动时的中断上传恢复；请重启以重放未确认完成记录：{error}")
            })?;
        }

        Ok(state)
    }
}

/// Interprets the persisted `storage.download_root` setting.
///
/// A blank or relative value degrades to `None` ("use the default root")
/// rather than to an error, so a bad setting can never stop the app from
/// launching -- the user has to be able to get in and fix it.
///
/// Pure so it can be tested without a store, a runtime, or a Tauri app.
fn resolve_download_root(configured: Option<&str>) -> Option<PathBuf> {
    let trimmed = configured?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        Some(path)
    } else {
        None
    }
}

fn persisted_from_sqlite(snapshot: AppStoreSnapshot) -> Result<PersistedStore, String> {
    let mut library = Vec::with_capacity(snapshot.library.len());
    for row in snapshot.library {
        let entry = serde_json::from_slice::<LibraryEntry>(&row.payload).map_err(|error| {
            format!(
                "application SQLite library row {} is corrupt: {error}",
                row.entry_key
            )
        })?;
        if entry.key() != row.entry_key {
            return Err(format!(
                "application SQLite library row key mismatch: stored {}, payload {}",
                row.entry_key,
                entry.key()
            ));
        }
        library.push(entry);
    }
    let storage = snapshot
        .storage
        .ok_or_else(|| "application SQLite store is missing its storage profile row".to_string())
        .and_then(|payload| {
            serde_json::from_slice::<StorageConfig>(&payload)
                .map_err(|error| format!("application SQLite storage row is corrupt: {error}"))
        })?;
    Ok(PersistedStore { library, storage })
}

/// Removes any legacy plaintext credential before SQLite becomes
/// authoritative. The replacement is atomic so a crash leaves either the
/// original recoverable JSON or the complete secret-free migration source.
fn rewrite_legacy_store(path: &PathBuf, payload: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("legacy store path has no parent: {path:?}"))?;
    let tmp = parent.join(format!(
        ".store-json-migration-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .map_err(|error| format!("failed to create legacy scrub file {tmp:?}: {error}"))?;
        file.write_all(payload)
            .map_err(|error| format!("failed to scrub legacy store {path:?}: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("failed to fsync legacy scrub file {tmp:?}: {error}"))?;
        drop(file);
        fs::rename(&tmp, path).map_err(|error| {
            format!("failed to publish scrubbed legacy store {path:?}: {error}")
        })?;
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to fsync legacy store directory: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Keeps the one-release rollback artifact required by ADR-PC-001, but only
/// after `rewrite_legacy_store` has removed every plaintext credential.
fn archive_legacy_store(path: &PathBuf) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("legacy store path has no parent: {path:?}"))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("system clock cannot timestamp legacy archive: {error}"))?
        .as_secs();
    let archive = parent.join(format!(
        "store.json.migrated-{timestamp}-{}",
        uuid::Uuid::new_v4().simple()
    ));
    fs::rename(path, &archive).map_err(|error| {
        format!("failed to archive scrubbed legacy store as {archive:?}: {error}")
    })?;
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to fsync legacy archive directory: {error}"))?;
    Ok(())
}

/// Reads a pre-PC-06 `store.json`'s `storage.accessKey`/`storage.secretKey`
/// plaintext fields directly out of the raw JSON, without going through
/// `PersistedStore`'s (now secret-free) `Deserialize` impl -- which would
/// just silently drop unknown fields. Returns `None` if the file isn't
/// JSON, has no `storage` object, or either field is absent/empty (an
/// empty string is treated the same as "never configured," matching
/// `StorageConfig::is_configured`'s own endpoint/bucket-only check).
fn extract_legacy_plaintext_credential(raw: &str) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let storage = value.get("storage")?;
    let access_key = storage.get("accessKey")?.as_str()?.trim();
    let secret_key = storage.get("secretKey")?.as_str()?.trim();
    if access_key.is_empty() || secret_key.is_empty() {
        return None;
    }
    Some((access_key.to_string(), secret_key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::models::PublicationEvidence;
    use rusqlite::Connection;
    use ylx_transfer_core::persistence::{JobStateTag, TransferStore, UploadJobSpec};

    #[cfg(feature = "demo")]
    #[test]
    fn demo_download_status_is_derived_in_evidence_priority_order() {
        assert_eq!(demo_download_status(false, []), DownloadStatus::None);
        assert_eq!(
            demo_download_status(false, [TransferState::Failed]),
            DownloadStatus::Failed
        );
        assert_eq!(
            demo_download_status(true, [TransferState::Failed]),
            DownloadStatus::Done
        );
        assert_eq!(
            demo_download_status(true, [TransferState::Failed, TransferState::Cancelling]),
            DownloadStatus::Downloading
        );
        assert_eq!(
            demo_download_status(false, [TransferState::Succeeded]),
            DownloadStatus::Done
        );
    }

    #[test]
    fn extract_legacy_plaintext_credential_finds_a_pre_pc06_store_json() {
        let raw = r#"{"library":[],"storage":{"endpoint":"https://s3.example","bucket":"b","accessKey":"AKIA123","secretKey":"topsecret","prefix":""}}"#;
        let found = extract_legacy_plaintext_credential(raw);
        assert_eq!(
            found,
            Some(("AKIA123".to_string(), "topsecret".to_string()))
        );
    }

    #[test]
    fn extract_legacy_plaintext_credential_is_none_for_current_secret_free_shape() {
        let raw = r#"{"library":[],"storage":{"endpoint":"https://s3.example","bucket":"b","prefix":""}}"#;
        assert_eq!(extract_legacy_plaintext_credential(raw), None);
    }

    #[test]
    fn extract_legacy_plaintext_credential_is_none_when_either_field_is_empty() {
        let raw = r#"{"storage":{"accessKey":"","secretKey":"x"}}"#;
        assert_eq!(extract_legacy_plaintext_credential(raw), None);
        let raw2 = r#"{"storage":{"accessKey":"x","secretKey":""}}"#;
        assert_eq!(extract_legacy_plaintext_credential(raw2), None);
    }

    #[test]
    fn extract_legacy_plaintext_credential_is_none_for_garbage_or_missing_file_content() {
        assert_eq!(extract_legacy_plaintext_credential(""), None);
        assert_eq!(extract_legacy_plaintext_credential("not json"), None);
        assert_eq!(
            extract_legacy_plaintext_credential(r#"{"library":[]}"#),
            None
        );
    }

    #[test]
    fn persisted_storage_config_json_never_contains_secret_key_names() {
        // The actual security property this task is about: prove a
        // `PersistedStore` snapshot -- the exact payload shape written into
        // SQLite rows and the legacy rollback archive -- can never carry the
        // secret structurally.
        let snapshot = PersistedStore {
            library: Vec::new(),
            storage: StorageConfig {
                endpoint: "https://s3.example.com".to_string(),
                bucket: "my-bucket".to_string(),
                prefix: "recordings".to_string(),
                url_style: crate::models::StorageUrlStyle::Path,
                download_root: Some("/data/ylx".to_string()),
            },
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        for needle in ["accessKey", "secretKey", "access_key", "secret_key"] {
            assert!(
                !json.contains(needle),
                "persisted JSON must never contain a {needle} field: {json}"
            );
        }
    }

    #[test]
    fn resolve_download_root_degrades_bad_settings_to_the_default() {
        assert_eq!(resolve_download_root(None), None);
        assert_eq!(resolve_download_root(Some("")), None);
        assert_eq!(resolve_download_root(Some("   ")), None);
        assert_eq!(resolve_download_root(Some("relative/dir")), None);
        let absolute = std::env::temp_dir().join("recordings");
        let padded = format!("  {}  ", absolute.display());
        assert_eq!(resolve_download_root(Some(&padded)), Some(absolute));
    }

    /// Regression: the first launch that migrates a legacy `store.json`
    /// must already use that store's custom download directory. The old
    /// two-read boot protocol picked the root from the (still empty) SQLite
    /// store before the legacy migration ran, so the whole migrating run
    /// downloaded into the default root and the user's configured directory
    /// only took effect on the *next* launch.
    #[test]
    fn legacy_custom_download_root_is_in_effect_during_the_migrating_run() {
        let dir =
            std::env::temp_dir().join(format!("ylx-state-boot-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let custom_root = dir.join("custom-library");
        std::fs::write(
            dir.join("store.json"),
            serde_json::to_vec(&serde_json::json!({
                "library": [],
                "storage": {
                    "endpoint": "https://s3.example",
                    "bucket": "b",
                    "prefix": "",
                    "urlStyle": "path",
                    "downloadRoot": custom_root.to_str().unwrap(),
                }
            }))
            .unwrap(),
        )
        .unwrap();

        // Boot stage 1 only: no SQLite storage row exists yet.
        let boot = BootConfig::load(dir.join("app-state.sqlite3")).expect("load boot config");
        assert_eq!(boot.download_root(), Some(custom_root));

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn corrupt_store_is_an_explicit_startup_error_instead_of_an_empty_library() {
        let dir = std::env::temp_dir().join(format!(
            "ylx-state-corrupt-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        std::fs::write(&path, b"not-json").unwrap();

        // AppState::new needs a full Composition and is covered at the
        // composition boundary; this assertion freezes the strict parser
        // used by that constructor so corruption can never become Default.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(serde_json::from_str::<PersistedStore>(&raw).is_err());

        std::fs::remove_dir_all(dir).ok();
    }

    /// A durable cancellation is committed before the reconciled library is
    /// written. If the authoritative AppStore commit then fails, the next
    /// start must be able to replay the still-unacknowledged cancellation
    /// instead of resurrecting the upload or cancelling it a second time.
    #[test]
    fn authoritative_startup_persist_failure_is_recoverable_on_the_second_start() {
        let dir = std::env::temp_dir().join(format!(
            "ylx-state-startup-persist-failure-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let app_store_path = dir.join("app-state.sqlite3");
        let transfer_store_path = dir.join("transfer_store.sqlite3");
        let entry = LibraryEntry {
            device_id: "dev-startup".to_string(),
            session_id: "sess-startup".to_string(),
            date_label: "2026-08-04".to_string(),
            downloaded_at: "2026-08-04T00:00:00Z".to_string(),
            bytes: 0,
            files: Vec::new(),
            complete: true,
            publication: Some(PublicationEvidence {
                revision: "revision-startup".to_string(),
                payload: Vec::new(),
                signature: Vec::new(),
                public_key: Vec::new(),
            }),
            library_root: None,
            object_receipts: Vec::new(),
            upload_projection: None,
            upload_status: crate::models::UploadStatus::Uploading,
            upload_retryable: false,
            uploaded_at: Some("2026-08-04T00:00:00Z".to_string()),
            upload_error: None,
        };
        let spec = UploadJobSpec::new(entry.key(), "revision-startup", "digest-startup")
            .expect("valid upload spec");

        // Seed both durable authorities before boot. The app store is made
        // authoritative (revision 1), so reconciliation's library rewrite
        // takes the explicit second persist branch in from_boot_config.
        let app_store = AppStore::open(&app_store_path).expect("open app store");
        app_store
            .save(
                &[AppLibraryPayload {
                    entry_key: entry.key(),
                    payload: serde_json::to_vec(&entry).expect("serialize library entry"),
                }],
                &serde_json::to_vec(&StorageConfig::default()).expect("serialize storage"),
            )
            .expect("seed app store");
        drop(app_store);
        let mut transfer_store =
            TransferStore::open(&transfer_store_path).expect("open transfer store");
        transfer_store
            .create_upload_job("upload-startup-persist-failure", &spec, "t0")
            .expect("seed interrupted upload");
        drop(transfer_store);

        let boot = BootConfig::load(app_store_path.clone()).expect("load first boot config");
        let composition = Composition::new(dir.clone(), dir.join("library"))
            .expect("construct inert composition");
        // Bump the durable revision from an independent connection after the
        // boot snapshot was loaded. The authoritative CAS commit now fails
        // immediately with a revision conflict, while the library payload
        // itself stays unchanged for the second-start recovery check.
        let injector = Connection::open(&app_store_path)
            .expect("open independent app-store conflict connection");
        injector
            .execute(
                "UPDATE app_store_meta SET value = '2' WHERE key = 'revision'",
                [],
            )
            .expect("inject app-store revision conflict");
        drop(injector);
        let first_error = match AppState::from_boot_config(boot, composition.clone()) {
            Ok(_) => panic!("startup must report an authoritative persist failure"),
            Err(error) => error,
        };
        assert!(
            first_error.contains("无法持久化启动时的中断上传恢复"),
            "{first_error}"
        );
        drop(composition);

        // The cancellation and outbox are durable even though the app-store
        // projection was not. This is the state the next launch must replay.
        let transfer_store =
            TransferStore::open(&transfer_store_path).expect("reopen transfer store");
        let cancelled = transfer_store
            .get_job("upload-startup-persist-failure")
            .expect("read cancelled upload")
            .expect("cancelled upload remains durable");
        assert_eq!(cancelled.state, JobStateTag::Cancelled);
        assert_eq!(cancelled.state_version, 2);
        let completion = transfer_store
            .completion("upload-startup-persist-failure")
            .expect("read cancellation completion")
            .expect("cancellation outbox remains durable");
        assert!(!completion.is_acknowledged());
        drop(transfer_store);

        let persisted = AppStore::open(&app_store_path)
            .expect("reopen app store after failed projection")
            .load()
            .expect("read unchanged app store");
        let persisted_entry: LibraryEntry = serde_json::from_slice(
            &persisted
                .library
                .first()
                .expect("library row survives failed projection")
                .payload,
        )
        .expect("decode unchanged library row");
        assert_eq!(
            persisted_entry.upload_status,
            crate::models::UploadStatus::Uploading
        );

        // The external writer's revision is durable, so the second boot must
        // accept it. Startup must leave the already-cancelled job at the same
        // version and avoid a second cancellation while the outbox awaits
        // normal projection.
        let boot = BootConfig::load(app_store_path).expect("load second boot config");
        let composition = Composition::new(dir.clone(), dir.join("library"))
            .expect("construct second inert composition");
        let state = AppState::from_boot_config(boot, composition.clone())
            .expect("second startup replays recoverable cancellation state");
        assert_eq!(
            state.0.lock().unwrap().library[0].upload_status,
            crate::models::UploadStatus::Uploading,
            "the outbox remains the authority until the normal projection consumer runs"
        );
        let transfer_store =
            TransferStore::open(dir.join("transfer_store.sqlite3")).expect("reopen transfer store");
        let second_job = transfer_store
            .get_job("upload-startup-persist-failure")
            .expect("read second-start upload")
            .expect("second-start upload remains durable");
        assert_eq!(second_job.state, JobStateTag::Cancelled);
        assert_eq!(second_job.state_version, 2);
        assert!(
            !transfer_store
                .completion("upload-startup-persist-failure")
                .unwrap()
                .unwrap()
                .is_acknowledged(),
            "second start must not acknowledge before projecting the library row"
        );
        drop(transfer_store);
        drop(state);
        drop(composition);
        std::fs::remove_dir_all(dir).ok();
    }
}
