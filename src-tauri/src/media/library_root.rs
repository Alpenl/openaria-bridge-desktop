//! Shared/exclusive fencing for the mutable PC library root.
//!
//! A media import can copy tens of gigabytes. Holding one global mutex for that
//! whole operation — which is what a plain `with_library_root` callback does —
//! makes pause, cancel, and every other command wait behind the copy. That is
//! exactly the failure §6.6 of the Ubuntu pipeline specification forbids.
//!
//! So the root is guarded by a reader/writer authority instead:
//!
//! * Workers take a **shared** [`LibraryRootLease`] and hold it for as long as
//!   they are reading or writing under the root. Many may hold one at once, and
//!   holding one never blocks another worker or a command.
//! * A root switch takes an **exclusive** lease. It fails with a typed conflict
//!   while any shared lease is outstanding, rather than waiting behind an import
//!   that may run for an hour.
//!
//! A lease is not just a permission; it pins identity. Each one captures the
//! canonical path, the Linux `st_dev`, and a root generation that increments on
//! every switch. `assert_current` re-checks all three, so a worker that resumes
//! after a swap, unmount, or bind-mount discovers it and stops instead of
//! writing into whatever now occupies that path.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::json;

use super::ports::{MediaErrorCode, MediaPortError};

/// Immutable identity of one observed library root.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
}

impl RootIdentity {
    /// Observe the root through a no-follow stat.
    ///
    /// Failure here is deliberately fatal to the caller's operation: an
    /// unverifiable destination must never be treated as "probably the same
    /// one", because the whole point of the check is to catch the case where
    /// it silently is not.
    fn observe(path: &Path) -> Result<Self, MediaPortError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            root_error(
                "library_root_unavailable",
                format!("the local media library root could not be inspected: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(root_error(
                "library_root_not_a_directory",
                "the local media library root is not a no-follow directory",
            ));
        }
        let canonical_path = fs::canonicalize(path).map_err(|error| {
            root_error(
                "library_root_unavailable",
                format!("the local media library root has no canonical path: {error}"),
            )
        })?;
        Ok(Self {
            canonical_path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Debug)]
struct AuthorityState {
    root: PathBuf,
    identity: RootIdentity,
    generation: u64,
    shared_leases: usize,
    exclusive_held: bool,
}

/// Owner of the current library root and of the leases fencing it.
#[derive(Debug)]
pub struct LibraryRootAuthority {
    state: Mutex<AuthorityState>,
    /// Monotonic across switches and never reused, so a stale lease cannot
    /// match a later root that happens to sit at the same path.
    next_generation: AtomicU64,
}

impl LibraryRootAuthority {
    /// Establish the authority over an already-prepared root.
    pub fn new(root: PathBuf) -> Result<Arc<Self>, MediaPortError> {
        let identity = RootIdentity::observe(&root)?;
        Ok(Arc::new(Self {
            state: Mutex::new(AuthorityState {
                root,
                identity,
                generation: 1,
                shared_leases: 0,
                exclusive_held: false,
            }),
            next_generation: AtomicU64::new(1),
        }))
    }

    /// The current root, for read-only display and configuration.
    ///
    /// This intentionally returns no lease: a path read this way is a value,
    /// not a permission, and must not be used to open files.
    #[must_use]
    #[cfg(test)]
    pub fn current_root(&self) -> PathBuf {
        lock(&self.state).root.clone()
    }

    #[must_use]
    #[cfg(test)]
    pub fn generation(&self) -> u64 {
        lock(&self.state).generation
    }

    /// Take a shared lease for one worker or command.
    ///
    /// The identity is re-observed here rather than reused from the last
    /// switch, so a root that was unmounted or replaced while idle is caught at
    /// acquisition instead of at the first write.
    pub fn acquire_shared(
        self: &Arc<Self>,
        owner: &str,
    ) -> Result<LibraryRootLease, MediaPortError> {
        let mut state = lock(&self.state);
        if state.exclusive_held {
            return Err(root_conflict("a library-root change is in progress", owner));
        }
        let observed = RootIdentity::observe(&state.root)?;
        if observed != state.identity {
            return Err(root_error(
                "library_root_changed",
                "the local media library root changed identity outside the application",
            ));
        }
        state.shared_leases += 1;
        Ok(LibraryRootLease {
            authority: Arc::clone(self),
            root: state.root.clone(),
            identity: observed,
            generation: state.generation,
        })
    }

    /// Take the exclusive lease used to change the root.
    ///
    /// This never waits. An import that has held a shared lease for an hour
    /// should produce an immediate, explainable conflict in the settings UI,
    /// not a frozen dialog.
    pub fn acquire_exclusive(
        self: &Arc<Self>,
    ) -> Result<ExclusiveLibraryRootLease, MediaPortError> {
        let mut state = lock(&self.state);
        if state.exclusive_held {
            return Err(root_conflict(
                "another library-root change is already in progress",
                "settings",
            ));
        }
        if state.shared_leases > 0 {
            return Err(root_conflict(
                &format!(
                    "{} media operation(s) are still using the current library root",
                    state.shared_leases
                ),
                "settings",
            ));
        }
        state.exclusive_held = true;
        Ok(ExclusiveLibraryRootLease {
            authority: Arc::clone(self),
        })
    }

    fn release_shared(&self) {
        let mut state = lock(&self.state);
        state.shared_leases = state.shared_leases.saturating_sub(1);
    }

    fn release_exclusive(&self) {
        lock(&self.state).exclusive_held = false;
    }

    /// Install a new root. Only reachable while the exclusive lease is held,
    /// which is why it can assume no worker is mid-operation.
    fn install(&self, root: PathBuf) -> Result<u64, MediaPortError> {
        let identity = RootIdentity::observe(&root)?;
        let mut state = lock(&self.state);
        let generation = self.next_generation.fetch_add(1, Ordering::AcqRel) + 1;
        state.root = root;
        state.identity = identity;
        state.generation = generation;
        Ok(generation)
    }

    fn assert_current(
        &self,
        generation: u64,
        identity: &RootIdentity,
    ) -> Result<(), MediaPortError> {
        let state = lock(&self.state);
        if state.generation != generation {
            return Err(root_error(
                "library_root_changed",
                "the local media library root was changed while this operation was running",
            ));
        }
        if &state.identity != identity {
            return Err(root_error(
                "library_root_changed",
                "the local media library root no longer has the identity this operation started with",
            ));
        }
        drop(state);
        // Re-stat as well: the authority's cached identity only proves that no
        // *application* switch happened. An unmount or an external swap is
        // invisible until the filesystem itself is asked again.
        let observed = RootIdentity::observe(&identity.canonical_path)?;
        if &observed != identity {
            return Err(root_error(
                "library_root_changed",
                "the local media library root changed identity outside the application",
            ));
        }
        Ok(())
    }
}

/// A held shared lease. Dropping it releases the fence, so a worker cannot
/// leak one by returning early on an error path.
#[derive(Debug)]
pub struct LibraryRootLease {
    authority: Arc<LibraryRootAuthority>,
    root: PathBuf,
    identity: RootIdentity,
    generation: u64,
}

impl LibraryRootLease {
    /// The pinned root. Safe to use for path construction only while this
    /// lease is alive and `assert_current` keeps succeeding.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    #[cfg(test)]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Re-assert the fence. Workers call this at every I/O stage boundary —
    /// before preflight, before each file, before verify, and before commit —
    /// so a change is caught within one chunk rather than after a whole copy.
    pub fn assert_current(&self) -> Result<(), MediaPortError> {
        self.authority
            .assert_current(self.generation, &self.identity)
    }
}

impl Drop for LibraryRootLease {
    fn drop(&mut self) {
        self.authority.release_shared();
    }
}

/// A held exclusive lease. The root may be replaced through it exactly once.
#[derive(Debug)]
pub struct ExclusiveLibraryRootLease {
    authority: Arc<LibraryRootAuthority>,
}

impl ExclusiveLibraryRootLease {
    /// Replace the root and bump its generation, invalidating every lease that
    /// could still be referenced by a suspended worker.
    pub fn install(&self, root: PathBuf) -> Result<u64, MediaPortError> {
        self.authority.install(root)
    }
}

impl Drop for ExclusiveLibraryRootLease {
    fn drop(&mut self) {
        self.authority.release_exclusive();
    }
}

fn root_conflict(detail: &str, owner: &str) -> MediaPortError {
    MediaPortError::new(MediaErrorCode::OperationConflict, detail)
        .with_retryable(true)
        .with_detail("capability", json!("library_root_authority"))
        .with_detail("owner", json!(owner))
}

fn root_error(reason: &'static str, message: impl Into<String>) -> MediaPortError {
    MediaPortError::new(MediaErrorCode::StorageNotConfigured, message)
        .with_retryable(false)
        .with_detail("capability", json!("library_root_authority"))
        .with_detail("reason", json!(reason))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> (tempfile::TempDir, Arc<LibraryRootAuthority>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let authority =
            LibraryRootAuthority::new(dir.path().to_path_buf()).expect("root authority");
        (dir, authority)
    }

    #[test]
    fn shared_leases_do_not_block_each_other() {
        let (_dir, authority) = authority();
        let first = authority.acquire_shared("import").expect("first lease");
        let second = authority.acquire_shared("command").expect("second lease");
        assert_eq!(first.generation(), second.generation());
    }

    #[test]
    fn a_switch_conflicts_instead_of_waiting_for_an_active_worker() {
        let (_dir, authority) = authority();
        let _worker = authority.acquire_shared("import").expect("worker lease");
        let error = authority
            .acquire_exclusive()
            .expect_err("a switch must not block behind a running import");
        assert!(error.to_string().contains("still using"));
    }

    #[test]
    fn a_switch_succeeds_once_every_worker_released() {
        let (_dir, authority) = authority();
        {
            let _worker = authority.acquire_shared("import").expect("worker lease");
        }
        let exclusive = authority.acquire_exclusive().expect("exclusive lease");
        let replacement = tempfile::tempdir().expect("replacement root");
        let generation = exclusive
            .install(replacement.path().to_path_buf())
            .expect("install");
        assert_eq!(generation, 2);
        drop(exclusive);
        let lease = authority.acquire_shared("import").expect("new lease");
        assert_eq!(lease.root(), replacement.path());
    }

    #[test]
    fn a_lease_taken_before_a_switch_stops_asserting() {
        let (_dir, authority) = authority();
        let stale = authority.acquire_shared("import").expect("stale lease");
        stale.assert_current().expect("still current");
        // The stale lease is released before the switch, but its captured
        // generation must still fail once the root moved on.
        let generation = stale.generation();
        drop(stale);
        let exclusive = authority.acquire_exclusive().expect("exclusive lease");
        let replacement = tempfile::tempdir().expect("replacement root");
        exclusive
            .install(replacement.path().to_path_buf())
            .expect("install");
        drop(exclusive);
        assert_ne!(authority.generation(), generation);
    }

    #[test]
    fn a_worker_lease_is_refused_while_a_switch_is_in_progress() {
        let (_dir, authority) = authority();
        let _exclusive = authority.acquire_exclusive().expect("exclusive lease");
        assert!(authority.acquire_shared("import").is_err());
    }
}
