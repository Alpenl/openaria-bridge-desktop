use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::normalization::{
    DerivationJobId, DerivedManifest, DerivedRevision, ProfileRevision, SegmentPairCheckpoint,
    SourceContentRevision,
};

const DERIVED_MANIFEST_NAME: &str = "derived_manifest.json";

#[cfg(all(test, unix))]
type StagingHook = Box<dyn FnOnce() + Send>;

#[cfg(all(test, unix))]
type StagingHookSlot = std::sync::OnceLock<std::sync::Mutex<Option<StagingHook>>>;

#[cfg(all(test, unix))]
static AFTER_PAIR_HASH_HOOK: StagingHookSlot = std::sync::OnceLock::new();

#[cfg(all(test, unix))]
static AFTER_WORK_PRECHECK_HOOK: StagingHookSlot = std::sync::OnceLock::new();

#[cfg(all(test, unix))]
pub(super) fn set_after_pair_hash_hook(hook: impl FnOnce() + Send + 'static) {
    let slot = AFTER_PAIR_HASH_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    *slot.lock().expect("pair hash hook lock") = Some(Box::new(hook));
}

#[cfg(all(test, unix))]
pub(super) fn set_after_work_precheck_hook(hook: impl FnOnce() + Send + 'static) {
    let slot = AFTER_WORK_PRECHECK_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    *slot.lock().expect("work precheck hook lock") = Some(Box::new(hook));
}

#[cfg(all(test, unix))]
fn run_after_pair_hash_hook() {
    let Some(slot) = AFTER_PAIR_HASH_HOOK.get() else {
        return;
    };
    if let Some(hook) = slot.lock().expect("pair hash hook lock").take() {
        hook();
    }
}

#[cfg(all(test, unix))]
fn run_after_work_precheck_hook() {
    let Some(slot) = AFTER_WORK_PRECHECK_HOOK.get() else {
        return;
    };
    if let Some(hook) = slot.lock().expect("work precheck hook lock").take() {
        hook();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("unsafe derived staging path: {0}")]
    UnsafePath(String),
    #[error("derived staging I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("verified pair {segment_index} is missing or differs from its durable checkpoint")]
    PairEvidenceMismatch { segment_index: u32 },
    #[error("derived destination exists but does not match revision {0}")]
    ExistingDerivativeMismatch(DerivedRevision),
    #[error("derived manifest serialization failed: {0}")]
    Manifest(String),
    #[error("quality report evidence for segment {segment_index} eye {eye} is missing or differs from its digest")]
    QualityReportMismatch {
        segment_index: u32,
        eye: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct PairWorkspace {
    pair_root: PathBuf,
    left_partial: PathBuf,
    right_partial: PathBuf,
    // The public paths are fd-backed views of this handle on Unix. Keeping
    // the handle alive makes encoder writes stay below the directory we
    // opened with openat even if a hostile actor swaps a parent.
    #[cfg(unix)]
    _anchor: std::sync::Arc<File>,
    #[cfg(unix)]
    _work_anchor: std::sync::Arc<File>,
}

impl PairWorkspace {
    #[must_use]
    pub fn pair_root(&self) -> &Path {
        &self.pair_root
    }

    #[must_use]
    pub fn left_partial(&self) -> &Path {
        &self.left_partial
    }

    #[must_use]
    pub fn right_partial(&self) -> &Path {
        &self.right_partial
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPair {
    pub relative_path: String,
    pub commit_receipt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingCommit {
    pub local_relative_path: String,
    pub local_commit_receipt: String,
    pub manifest_sha256: String,
    pub output_inventory_sha256: String,
    pub reused_existing: bool,
}

/// Filesystem transaction owner for `.ylx-derived-staging` and immutable
/// `derivatives`. Both trees live below one configured library root so every
/// publish uses a same-filesystem atomic directory rename.
#[derive(Debug, Clone)]
pub struct DerivedStaging {
    library_root: PathBuf,
}

impl DerivedStaging {
    #[must_use]
    pub fn new(library_root: impl Into<PathBuf>) -> Self {
        Self {
            library_root: library_root.into(),
        }
    }

    #[must_use]
    pub fn library_root(&self) -> &Path {
        &self.library_root
    }

    pub fn prepare_job(&self, job_id: &DerivationJobId) -> Result<(), StagingError> {
        #[cfg(unix)]
        {
            let root = open_library_root(&self.library_root)?;
            let staging = open_or_create_directory(&root, ".ylx-derived-staging")?;
            let job = open_or_create_directory(&staging, &path_component(job_id.as_str()))?;
            let video = open_or_create_directory(&job, "video")?;
            let pairs = open_or_create_directory(&video, "pairs")?;
            sync_directory_handle(&pairs)?;
            sync_directory_handle(&video)?;
            sync_directory_handle(&job)?;
            sync_directory_handle(&staging)
        }
        #[cfg(not(unix))]
        {
            ensure_directory(&self.library_root)?;
            let staging_parent = self.library_root.join(".ylx-derived-staging");
            ensure_directory(&staging_parent)?;
            let job = staging_parent.join(path_component(job_id.as_str()));
            ensure_directory(&job)?;
            let video = job.join("video");
            ensure_directory(&video)?;
            ensure_directory(&video.join("pairs"))?;
            sync_directory(&video)?;
            sync_directory(&job)?;
            sync_directory(&staging_parent)
        }
    }

    pub fn prepare_pair(
        &self,
        job_id: &DerivationJobId,
        segment_index: u32,
    ) -> Result<PairWorkspace, StagingError> {
        self.prepare_job(job_id)?;
        #[cfg(unix)]
        {
            let pairs = self.pairs_directory(job_id)?;
            let work_name = format!(".{segment_index:05}.work");
            remove_child_tree_if_present(&pairs, &work_name)?;
            let pair = open_or_create_directory(&pairs, &work_name)?;
            sync_directory_handle(&pairs)?;
            Ok(workspace_from_parent_anchor(pairs, pair, &work_name))
        }
        #[cfg(not(unix))]
        {
            let workspace = self.workspace(job_id, segment_index)?;
            remove_scoped_tree_if_present(&workspace.pair_root)?;
            ensure_directory(&workspace.pair_root)?;
            sync_directory(
                workspace
                    .pair_root
                    .parent()
                    .expect("pair work directory always has a parent"),
            )?;
            Ok(workspace)
        }
    }

    /// An uncheckpointed final-named pair can exist only after a crash
    /// between directory rename and SQLite CAS. Move it back behind the
    /// partial boundary so the full quality/structure/decode gate can run
    /// again without another lossy encode.
    #[allow(unreachable_code)]
    pub fn recover_uncheckpointed_pair(
        &self,
        job_id: &DerivationJobId,
        segment_index: u32,
    ) -> Result<Option<PairWorkspace>, StagingError> {
        #[cfg(unix)]
        {
            self.prepare_job(job_id)?;
            let pairs = self.pairs_directory(job_id)?;
            let final_name = format!("{segment_index:05}");
            match open_existing_directory(&pairs, &final_name) {
                Ok(_) => {}
                Err(StagingError::Io { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    return Ok(None)
                }
                Err(error) => return Err(error),
            }
            let work_name = format!(".{segment_index:05}.work");
            remove_child_tree_if_present(&pairs, &work_name)?;
            rename_child(&pairs, &final_name, &pairs, &work_name)?;
            // The directory formerly named final is now the work entry. Open
            // it only after renameat: a handle to a pre-created empty work
            // directory would be detached from the recovered contents.
            let work = open_existing_directory(&pairs, &work_name)?;
            sync_directory_handle(&pairs)?;
            let workspace = workspace_from_parent_anchor(pairs, work, &work_name);
            let work_path = fd_path(&workspace._work_anchor);
            let left_final = work_path.join("left.mp4");
            let right_final = work_path.join("right.mp4");
            require_nonempty_regular_file(&left_final)?;
            require_nonempty_regular_file(&right_final)?;
            fs::rename(&left_final, &workspace.left_partial)
                .map_err(|source| io_error(&left_final, source))?;
            fs::rename(&right_final, &workspace.right_partial)
                .map_err(|source| io_error(&right_final, source))?;
            return Ok(Some(workspace));
        }
        self.prepare_job(job_id)?;
        let final_dir = self.published_pair_path(job_id, segment_index);
        if !path_exists(&final_dir)? {
            return Ok(None);
        }
        require_regular_directory(&final_dir)?;
        let workspace = self.prepare_pair(job_id, segment_index)?;
        fs::remove_dir(&workspace.pair_root)
            .map_err(|source| io_error(&workspace.pair_root, source))?;
        fs::rename(&final_dir, &workspace.pair_root)
            .map_err(|source| io_error(&final_dir, source))?;

        let work_path = workspace.pair_root.clone();
        let left_final = work_path.join("left.mp4");
        let right_final = work_path.join("right.mp4");
        require_nonempty_regular_file(&left_final)?;
        require_nonempty_regular_file(&right_final)?;
        fs::rename(&left_final, &workspace.left_partial)
            .map_err(|source| io_error(&left_final, source))?;
        fs::rename(&right_final, &workspace.right_partial)
            .map_err(|source| io_error(&right_final, source))?;
        sync_directory(&workspace.pair_root)?;
        sync_directory(
            workspace
                .pair_root
                .parent()
                .expect("pair work directory always has a parent"),
        )?;
        Ok(Some(workspace))
    }

    #[allow(unreachable_code)]
    pub fn discard_partial_pair(
        &self,
        job_id: &DerivationJobId,
        segment_index: u32,
    ) -> Result<(), StagingError> {
        #[cfg(unix)]
        {
            let pairs = self.pairs_directory(job_id)?;
            remove_child_tree_if_present(&pairs, &format!(".{segment_index:05}.work"))?;
            return sync_directory_handle(&pairs);
        }
        let workspace = self.workspace(job_id, segment_index)?;
        remove_scoped_tree_if_present(&workspace.pair_root)?;
        if let Some(parent) = workspace.pair_root.parent() {
            if path_exists(parent)? {
                sync_directory(parent)?;
            }
        }
        Ok(())
    }

    /// Remove both a hidden work pair and an uncheckpointed final-named pair.
    /// This is used only for the current pair after a stop request; durable
    /// checkpoints are never removed by this method.
    #[allow(unreachable_code)]
    pub fn discard_pair(
        &self,
        job_id: &DerivationJobId,
        segment_index: u32,
    ) -> Result<(), StagingError> {
        #[cfg(unix)]
        {
            let pairs = self.pairs_directory(job_id)?;
            remove_child_tree_if_present(&pairs, &format!(".{segment_index:05}.work"))?;
            remove_child_tree_if_present(&pairs, &format!("{segment_index:05}"))?;
            return sync_directory_handle(&pairs);
        }
        self.discard_partial_pair(job_id, segment_index)?;
        let published = self.published_pair_path(job_id, segment_index);
        remove_scoped_tree_if_present(&published)?;
        if let Some(parent) = published.parent() {
            if path_exists(parent)? {
                sync_directory(parent)?;
            }
        }
        Ok(())
    }

    /// Rename both closed outputs inside the hidden work directory, fsync it,
    /// then publish the containing directory once. A ledger checkpoint is
    /// written only after this method succeeds, so one eye is never durable
    /// without the other. On Unix success means the final entry named the
    /// held, hashed work inode when this method returned. The private staging
    /// tree is owner-only; a same-UID writer that can still mutate it after
    /// return must be fenced by the library owner's consumer revalidation.
    pub fn publish_validated_pair(
        &self,
        job_id: &DerivationJobId,
        segment_index: u32,
        left_sha256: &str,
        right_sha256: &str,
    ) -> Result<PublishedPair, StagingError> {
        let workspace = self.workspace(job_id, segment_index)?;
        require_nonempty_regular_file(&workspace.left_partial)?;
        require_nonempty_regular_file(&workspace.right_partial)?;
        let observed_left = sha256_file(&workspace.left_partial)?;
        let observed_right = sha256_file(&workspace.right_partial)?;
        if observed_left != left_sha256 || observed_right != right_sha256 {
            return Err(StagingError::PairEvidenceMismatch { segment_index });
        }
        #[cfg(all(test, unix))]
        run_after_pair_hash_hook();

        #[cfg(unix)]
        let work_path = fd_path(&workspace._work_anchor);
        #[cfg(not(unix))]
        let work_path = workspace.pair_root.clone();
        let left_final = work_path.join("left.mp4");
        let right_final = work_path.join("right.mp4");
        fs::rename(&workspace.left_partial, &left_final)
            .map_err(|source| io_error(&workspace.left_partial, source))?;
        fs::rename(&workspace.right_partial, &right_final)
            .map_err(|source| io_error(&workspace.right_partial, source))?;
        // Re-read the final names through the held work-directory FD.  A
        // partial name replaced after its first hash therefore cannot reach
        // the directory publish step with the originally supplied evidence.
        if sha256_file(&left_final)? != left_sha256 || sha256_file(&right_final)? != right_sha256 {
            return Err(StagingError::PairEvidenceMismatch { segment_index });
        }
        #[cfg(unix)]
        sync_directory_handle(&workspace._work_anchor)?;
        #[cfg(not(unix))]
        sync_directory(&workspace.pair_root)?;

        let published = workspace
            .pair_root
            .parent()
            .expect("workspace pair path always has a parent")
            .join(format!("{segment_index:05}"));
        if path_exists(&published)? {
            return Err(StagingError::PairEvidenceMismatch { segment_index });
        }
        #[cfg(unix)]
        {
            let pairs = workspace._anchor.as_ref();
            let work_name = format!(".{segment_index:05}.work");
            ensure_child_identity(pairs, &work_name, &workspace._work_anchor)?;
            #[cfg(all(test, unix))]
            run_after_work_precheck_hook();
            rename_child(pairs, &work_name, pairs, &format!("{segment_index:05}"))?;
            let final_name = format!("{segment_index:05}");
            if ensure_child_identity(pairs, &final_name, &workspace._work_anchor).is_err() {
                // The namespace changed between precheck and renameat. The
                // replacement is never a consumable final pair: unlink it only
                // through the trusted parent FD, without following symlinks.
                remove_child_tree_if_present(pairs, &final_name)?;
                return Err(StagingError::UnsafePath(
                    "work entry changed during atomic publish".to_string(),
                ));
            }
            sync_directory_handle(pairs)?;
        }
        #[cfg(not(unix))]
        {
            #[cfg(all(test, unix))]
            run_after_work_precheck_hook();
            fs::rename(&workspace.pair_root, &published)
                .map_err(|source| io_error(&workspace.pair_root, source))?;
            sync_directory(
                published
                    .parent()
                    .expect("published pair path always has a parent"),
            )?;
        }

        Ok(PublishedPair {
            relative_path: format!("video/pairs/{segment_index:05}"),
            commit_receipt: format!(
                "pair-directory-fsync:{segment_index}:{left_sha256}:{right_sha256}"
            ),
        })
    }

    #[allow(unreachable_code)]
    pub fn verify_checkpoint(
        &self,
        job_id: &DerivationJobId,
        checkpoint: &SegmentPairCheckpoint,
    ) -> Result<(), StagingError> {
        #[cfg(unix)]
        {
            let pairs = self.pairs_directory(job_id)?;
            let pair =
                open_existing_directory(&pairs, &format!("{:05}", checkpoint.segment_index()))?;
            let pair_path = fd_path(&pair);
            return verify_file(
                &pair_path.join("left.mp4"),
                checkpoint.left().size_bytes(),
                checkpoint.left().sha256().as_str(),
            )
            .and_then(|()| {
                verify_file(
                    &pair_path.join("right.mp4"),
                    checkpoint.right().size_bytes(),
                    checkpoint.right().sha256().as_str(),
                )
            })
            .map_err(|_| StagingError::PairEvidenceMismatch {
                segment_index: checkpoint.segment_index(),
            });
        }
        let pair = self.published_pair_path(job_id, checkpoint.segment_index());
        let left = pair.join("left.mp4");
        let right = pair.join("right.mp4");
        verify_file(
            &left,
            checkpoint.left().size_bytes(),
            checkpoint.left().sha256().as_str(),
        )
        .and_then(|()| {
            verify_file(
                &right,
                checkpoint.right().size_bytes(),
                checkpoint.right().sha256().as_str(),
            )
        })
        .map_err(|_| StagingError::PairEvidenceMismatch {
            segment_index: checkpoint.segment_index(),
        })
    }

    #[allow(unreachable_code)]
    pub fn commit_derivative(
        &self,
        job_id: &DerivationJobId,
        source_revision: &SourceContentRevision,
        profile_revision: &ProfileRevision,
        manifest: &DerivedManifest,
    ) -> Result<StagingCommit, StagingError> {
        #[cfg(unix)]
        {
            let root = open_library_root(&self.library_root)?;
            let staging_parent = open_existing_directory(&root, ".ylx-derived-staging")?;
            let job_name = path_component(job_id.as_str());
            let staging_dir = open_existing_directory(&staging_parent, &job_name)?;
            let staging_path = fd_path(&staging_dir);
            for output in manifest.output_inventory() {
                verify_file(
                    &staging_path.join(safe_relative(output.relative_path())?),
                    output.size_bytes(),
                    output.sha256().as_str(),
                )
                .map_err(|_| StagingError::PairEvidenceMismatch {
                    segment_index: output.segment_index(),
                })?;
            }
            verify_quality_reports(&staging_path, manifest)?;
            let partial = staging_path.join("derived_manifest.partial.json");
            let final_manifest = staging_path.join(DERIVED_MANIFEST_NAME);
            remove_regular_file_if_present(&partial)?;
            write_new_synced_file(&partial, manifest.canonical_bytes())?;
            if path_exists(&final_manifest)? {
                let existing = fs::read(&final_manifest)
                    .map_err(|source| io_error(&final_manifest, source))?;
                if existing != manifest.canonical_bytes() {
                    return Err(StagingError::ExistingDerivativeMismatch(
                        manifest.derived_revision().clone(),
                    ));
                }
                remove_regular_file_if_present(&partial)?;
            } else {
                fs::rename(&partial, &final_manifest)
                    .map_err(|source| io_error(&partial, source))?;
            }
            sync_directory_handle(&staging_dir)?;

            let local_relative_path = derivative_relative_path(
                source_revision,
                profile_revision,
                manifest.derived_revision(),
            );
            let derivatives = open_or_create_directory(&root, "derivatives")?;
            let source =
                open_or_create_directory(&derivatives, &path_component(source_revision.as_str()))?;
            let profile =
                open_or_create_directory(&source, &path_component(profile_revision.as_str()))?;
            let destination_name = path_component(manifest.derived_revision().as_str());
            let reused_existing = match open_existing_directory(&profile, &destination_name) {
                Ok(existing) => {
                    verify_existing_derivative(&fd_path(&existing), manifest)?;
                    remove_child_tree_if_present(&staging_parent, &job_name)?;
                    true
                }
                Err(StagingError::Io { source, .. })
                    if source.kind() == io::ErrorKind::NotFound =>
                {
                    rename_child(&staging_parent, &job_name, &profile, &destination_name)?;
                    false
                }
                Err(error) => return Err(error),
            };
            sync_directory_handle(&profile)?;
            let manifest_sha256 = sha256_bytes(manifest.canonical_bytes());
            let output_inventory_bytes = serde_json::to_vec(manifest.output_inventory())
                .map_err(|error| StagingError::Manifest(error.to_string()))?;
            return Ok(StagingCommit {
                local_relative_path,
                local_commit_receipt: format!(
                    "derived-directory-fsync:{}",
                    manifest.derived_revision().as_str()
                ),
                manifest_sha256,
                output_inventory_sha256: sha256_bytes(&output_inventory_bytes),
                reused_existing,
            });
        }
        for output in manifest.output_inventory() {
            let checkpoint_path = self
                .job_root(job_id)
                .join(safe_relative(output.relative_path())?);
            verify_file(
                &checkpoint_path,
                output.size_bytes(),
                output.sha256().as_str(),
            )
            .map_err(|_| StagingError::PairEvidenceMismatch {
                segment_index: output.segment_index(),
            })?;
        }
        verify_quality_reports(&self.job_root(job_id), manifest)?;

        let staging = self.job_root(job_id);
        let manifest_path = staging.join(DERIVED_MANIFEST_NAME);
        let manifest_partial = staging.join("derived_manifest.partial.json");
        remove_regular_file_if_present(&manifest_partial)?;
        write_new_synced_file(&manifest_partial, manifest.canonical_bytes())?;
        if path_exists(&manifest_path)? {
            let existing =
                fs::read(&manifest_path).map_err(|source| io_error(&manifest_path, source))?;
            if existing != manifest.canonical_bytes() {
                return Err(StagingError::ExistingDerivativeMismatch(
                    manifest.derived_revision().clone(),
                ));
            }
            remove_regular_file_if_present(&manifest_partial)?;
        } else {
            fs::rename(&manifest_partial, &manifest_path)
                .map_err(|source| io_error(&manifest_partial, source))?;
        }
        sync_directory(&staging)?;

        let local_relative_path = derivative_relative_path(
            source_revision,
            profile_revision,
            manifest.derived_revision(),
        );
        let destination = self.library_root.join(safe_relative(&local_relative_path)?);
        let destination_parent = destination
            .parent()
            .expect("derived revision path always has a parent");
        ensure_directory(destination_parent)?;

        let reused_existing = if path_exists(&destination)? {
            verify_existing_derivative(&destination, manifest)?;
            remove_scoped_tree_if_present(&staging)?;
            true
        } else {
            fs::rename(&staging, &destination).map_err(|source| io_error(&staging, source))?;
            false
        };
        sync_directory(destination_parent)?;

        let manifest_sha256 = sha256_bytes(manifest.canonical_bytes());
        let output_inventory_bytes = serde_json::to_vec(manifest.output_inventory())
            .map_err(|error| StagingError::Manifest(error.to_string()))?;
        Ok(StagingCommit {
            local_relative_path,
            local_commit_receipt: format!(
                "derived-directory-fsync:{}",
                manifest.derived_revision().as_str()
            ),
            manifest_sha256,
            output_inventory_sha256: sha256_bytes(&output_inventory_bytes),
            reused_existing,
        })
    }

    fn job_root(&self, job_id: &DerivationJobId) -> PathBuf {
        self.library_root
            .join(".ylx-derived-staging")
            .join(path_component(job_id.as_str()))
    }

    #[cfg(unix)]
    fn pairs_directory(&self, job_id: &DerivationJobId) -> Result<File, StagingError> {
        let root = open_library_root(&self.library_root)?;
        let staging = open_existing_directory(&root, ".ylx-derived-staging")?;
        let job = open_existing_directory(&staging, &path_component(job_id.as_str()))?;
        let video = open_existing_directory(&job, "video")?;
        open_existing_directory(&video, "pairs")
    }

    fn workspace(
        &self,
        job_id: &DerivationJobId,
        segment_index: u32,
    ) -> Result<PairWorkspace, StagingError> {
        #[cfg(unix)]
        {
            let pairs = self.pairs_directory(job_id)?;
            let work_name = format!(".{segment_index:05}.work");
            let pair = open_existing_directory(&pairs, &work_name)?;
            Ok(workspace_from_parent_anchor(pairs, pair, &work_name))
        }
        #[cfg(not(unix))]
        {
            let pair_root = self
                .job_root(job_id)
                .join("video")
                .join("pairs")
                .join(format!(".{segment_index:05}.work"));
            Ok(PairWorkspace {
                left_partial: pair_root.join("left.partial.mp4"),
                right_partial: pair_root.join("right.partial.mp4"),
                pair_root,
            })
        }
    }

    fn published_pair_path(&self, job_id: &DerivationJobId, segment_index: u32) -> PathBuf {
        self.job_root(job_id)
            .join("video")
            .join("pairs")
            .join(format!("{segment_index:05}"))
    }
}

fn derivative_relative_path(
    source: &SourceContentRevision,
    profile: &ProfileRevision,
    derived: &DerivedRevision,
) -> String {
    format!(
        "derivatives/{}/{}/{}",
        path_component(source.as_str()),
        path_component(profile.as_str()),
        path_component(derived.as_str())
    )
}

#[cfg(unix)]
fn open_library_root(path: &Path) -> Result<File, StagingError> {
    open_directory_path(path)
}

#[cfg(unix)]
fn open_directory_path(path: &Path) -> Result<File, StagingError> {
    let bytes = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| StagingError::UnsafePath(path.display().to_string()))?;
    // SAFETY: `bytes` is NUL-terminated and remains live for the call.
    let fd = unsafe {
        libc::open(
            bytes.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io_error(path, io::Error::last_os_error()));
    }
    // SAFETY: `open` returned a unique owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_existing_directory(parent: &File, name: &str) -> Result<File, StagingError> {
    open_directory_at(parent, name, false)
}

#[cfg(unix)]
fn open_or_create_directory(parent: &File, name: &str) -> Result<File, StagingError> {
    let directory = open_directory_at(parent, name, true)?;
    // Staging and derivative transaction directories are private to the
    // library owner. This is an explicit trusted-writer boundary, not a
    // claim that a malicious same-UID process is impossible.
    // SAFETY: directory is an owned open directory descriptor.
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(StagingError::Io {
            path: PathBuf::from(name),
            source: io::Error::last_os_error(),
        });
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &str, create: bool) -> Result<File, StagingError> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| StagingError::UnsafePath("directory component contains NUL".to_string()))?;
    if create {
        // SAFETY: valid directory descriptor and NUL-terminated single component.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(StagingError::Io {
                    path: PathBuf::from(name.to_string_lossy().into_owned()),
                    source: error,
                });
            }
        }
    }
    // SAFETY: valid directory descriptor and NUL-terminated single component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(StagingError::Io {
            path: PathBuf::from(name.to_string_lossy().into_owned()),
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: openat returned a unique owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn sync_directory_handle(directory: &File) -> Result<(), StagingError> {
    directory.sync_all().map_err(|source| StagingError::Io {
        path: PathBuf::from("<trusted-dirfd>"),
        source,
    })
}

#[cfg(all(unix, target_os = "macos"))]
fn fd_path(directory: &File) -> PathBuf {
    let mut buffer = [0 as libc::c_char; 1024];
    // SAFETY: F_GETPATH writes a NUL-terminated path into the provided
    // MAXPATHLEN-sized buffer for a valid open descriptor.
    let result =
        unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) };
    if result != 0 {
        return PathBuf::from(format!("/dev/fd/{}", directory.as_raw_fd()));
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
        .to_bytes()
        .to_vec();
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn fd_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

#[cfg(unix)]
fn rename_child(
    from_parent: &File,
    from: &str,
    to_parent: &File,
    to: &str,
) -> Result<(), StagingError> {
    let from = std::ffi::CString::new(from)
        .map_err(|_| StagingError::UnsafePath("directory component contains NUL".to_string()))?;
    let to = std::ffi::CString::new(to)
        .map_err(|_| StagingError::UnsafePath("directory component contains NUL".to_string()))?;
    // SAFETY: both descriptors are open directories and names are single NUL-terminated components.
    if unsafe {
        libc::renameat(
            from_parent.as_raw_fd(),
            from.as_ptr(),
            to_parent.as_raw_fd(),
            to.as_ptr(),
        )
    } != 0
    {
        return Err(StagingError::Io {
            path: PathBuf::from(to.to_string_lossy().into_owned()),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_child_identity(parent: &File, name: &str, expected: &File) -> Result<(), StagingError> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| StagingError::UnsafePath("directory component contains NUL".to_string()))?;
    let mut entry = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid descriptors and writable stat buffers.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            entry.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || unsafe { libc::fstat(expected.as_raw_fd(), held.as_mut_ptr()) } != 0
    {
        return Err(StagingError::UnsafePath(
            "work directory disappeared during publish".to_string(),
        ));
    }
    // SAFETY: both syscalls initialized their buffers.
    let entry = unsafe { entry.assume_init() };
    let held = unsafe { held.assume_init() };
    if entry.st_dev != held.st_dev
        || entry.st_ino != held.st_ino
        || (entry.st_mode & libc::S_IFMT) != libc::S_IFDIR
    {
        return Err(StagingError::UnsafePath(
            "work directory entry changed during publish".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn workspace_from_parent_anchor(parent: File, work: File, name: &str) -> PairWorkspace {
    let anchor = std::sync::Arc::new(parent);
    let work_anchor = std::sync::Arc::new(work);
    let pair_root = fd_path(&anchor).join(name);
    PairWorkspace {
        left_partial: fd_path(&work_anchor).join("left.partial.mp4"),
        right_partial: fd_path(&work_anchor).join("right.partial.mp4"),
        pair_root,
        _anchor: anchor,
        _work_anchor: work_anchor,
    }
}

#[cfg(unix)]
fn remove_child_tree_if_present(parent: &File, name: &str) -> Result<(), StagingError> {
    let name_c = std::ffi::CString::new(name)
        .map_err(|_| StagingError::UnsafePath("directory component contains NUL".to_string()))?;
    // SAFETY: valid directory descriptor and component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(StagingError::Io {
                path: PathBuf::from(name),
                source: error,
            })
        };
    }
    // SAFETY: openat returned a unique owned descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    remove_directory_contents(&directory)?;
    // SAFETY: valid directory descriptor and component; the child was emptied through its fd.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(StagingError::Io {
            path: PathBuf::from(name),
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn remove_directory_contents(directory: &File) -> Result<(), StagingError> {
    let proc_path = fd_path(directory);
    for entry in fs::read_dir(&proc_path).map_err(|source| io_error(&proc_path, source))? {
        let entry = entry.map_err(|source| io_error(&proc_path, source))?;
        let name = std::ffi::CString::new(entry.file_name().as_encoded_bytes())
            .map_err(|_| StagingError::UnsafePath("directory entry contains NUL".to_string()))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: valid descriptor, name and writable stat buffer.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(StagingError::Io {
                path: proc_path.clone(),
                source: io::Error::last_os_error(),
            });
        }
        // SAFETY: fstatat above initialized the buffer.
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            let child = open_existing_directory(directory, &name.to_string_lossy())?;
            remove_directory_contents(&child)?;
            // SAFETY: child is empty and name is a single component.
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(StagingError::Io {
                    path: proc_path.clone(),
                    source: io::Error::last_os_error(),
                });
            }
        } else {
            // SAFETY: unlinkat removes this directory entry without following it.
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(StagingError::Io {
                    path: proc_path.clone(),
                    source: io::Error::last_os_error(),
                });
            }
        }
    }
    Ok(())
}

fn verify_existing_derivative(
    destination: &Path,
    manifest: &DerivedManifest,
) -> Result<(), StagingError> {
    require_regular_directory(destination)?;
    let manifest_path = destination.join(DERIVED_MANIFEST_NAME);
    let bytes = fs::read(&manifest_path).map_err(|source| io_error(&manifest_path, source))?;
    if bytes != manifest.canonical_bytes() {
        return Err(StagingError::ExistingDerivativeMismatch(
            manifest.derived_revision().clone(),
        ));
    }
    for output in manifest.output_inventory() {
        let path = destination.join(safe_relative(output.relative_path())?);
        verify_file(&path, output.size_bytes(), output.sha256().as_str()).map_err(|_| {
            StagingError::ExistingDerivativeMismatch(manifest.derived_revision().clone())
        })?;
    }
    verify_quality_reports(destination, manifest).map_err(|_| {
        StagingError::ExistingDerivativeMismatch(manifest.derived_revision().clone())
    })?;
    Ok(())
}

fn verify_quality_reports(
    derivative_root: &Path,
    manifest: &DerivedManifest,
) -> Result<(), StagingError> {
    for validation in manifest.segment_validation() {
        let left = manifest
            .output_inventory()
            .iter()
            .find(|output| {
                output.segment_index() == validation.segment_index()
                    && output.role() == crate::normalization::DerivedOutputRole::VideoLeft
            })
            .ok_or(StagingError::QualityReportMismatch {
                segment_index: validation.segment_index(),
                eye: "left",
            })?;
        let right = manifest
            .output_inventory()
            .iter()
            .find(|output| {
                output.segment_index() == validation.segment_index()
                    && output.role() == crate::normalization::DerivedOutputRole::VideoRight
            })
            .ok_or(StagingError::QualityReportMismatch {
                segment_index: validation.segment_index(),
                eye: "right",
            })?;
        verify_quality_report(
            derivative_root,
            left.relative_path(),
            "left.quality-report.json",
            validation.left_quality().report_digest().as_str(),
            validation.segment_index(),
            "left",
        )?;
        verify_quality_report(
            derivative_root,
            right.relative_path(),
            "right.quality-report.json",
            validation.right_quality().report_digest().as_str(),
            validation.segment_index(),
            "right",
        )?;
    }
    Ok(())
}

fn verify_quality_report(
    derivative_root: &Path,
    output_relative_path: &str,
    report_name: &str,
    expected_sha256: &str,
    segment_index: u32,
    eye: &'static str,
) -> Result<(), StagingError> {
    let output_relative = safe_relative(output_relative_path)?;
    let pair_root = output_relative
        .parent()
        .ok_or(StagingError::QualityReportMismatch { segment_index, eye })?;
    let report = derivative_root
        .join(pair_root)
        .join("quality-report")
        .join(report_name);
    let size = require_nonempty_regular_file(&report)
        .map_err(|_| StagingError::QualityReportMismatch { segment_index, eye })?;
    if size > 1024 * 1024 || sha256_file(&report)? != expected_sha256 {
        return Err(StagingError::QualityReportMismatch { segment_index, eye });
    }
    Ok(())
}

fn verify_file(path: &Path, expected_size: u64, expected_sha256: &str) -> Result<(), StagingError> {
    let size = require_nonempty_regular_file(path)?;
    if size != expected_size || sha256_file(path)? != expected_sha256 {
        return Err(StagingError::UnsafePath(format!(
            "file evidence mismatch at {}",
            path.display()
        )));
    }
    Ok(())
}

fn require_nonempty_regular_file(path: &Path) -> Result<u64, StagingError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(StagingError::UnsafePath(format!(
            "{} is not a non-empty regular file",
            path.display()
        )));
    }
    Ok(metadata.len())
}

fn require_regular_directory(path: &Path) -> Result<(), StagingError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StagingError::UnsafePath(format!(
            "{} is not a regular directory",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), StagingError> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
    require_regular_directory(path)
}

fn write_new_synced_file(path: &Path, bytes: &[u8]) -> Result<(), StagingError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error(path, source))?;
    file.sync_all().map_err(|source| io_error(path, source))?;
    drop(file);
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StagingError> {
    let directory = File::open(path).map_err(|source| io_error(path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), StagingError> {
    // Windows has no portable directory-handle fsync. File contents are
    // still flushed before every rename; the platform adapter may add a
    // stronger volume-specific barrier when available.
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, StagingError> {
    let mut file = File::open(path).map_err(|source| io_error(path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| io_error(path, source))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn remove_regular_file_if_present(path: &Path) -> Result<(), StagingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(StagingError::UnsafePath(format!(
                "refusing to remove non-regular file {}",
                path.display()
            )))
        }
        Ok(_) => fs::remove_file(path).map_err(|source| io_error(path, source)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn remove_scoped_tree_if_present(path: &Path) -> Result<(), StagingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(StagingError::UnsafePath(
            format!("refusing to traverse staging symlink {}", path.display()),
        )),
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(path).map_err(|source| io_error(path, source))
        }
        Ok(_) => Err(StagingError::UnsafePath(format!(
            "refusing to remove non-directory staging path {}",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn path_exists(path: &Path) -> Result<bool, StagingError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn safe_relative(value: &str) -> Result<PathBuf, StagingError> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component.as_os_str().to_string_lossy().contains(':')
        })
    {
        return Err(StagingError::UnsafePath(value.to_string()));
    }
    Ok(path.to_path_buf())
}

fn path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex(byte >> 4));
            encoded.push(hex(byte & 0x0f));
        }
    }
    encoded
}

fn hex(value: u8) -> char {
    char::from(if value < 10 {
        b'0' + value
    } else {
        b'A' + value - 10
    })
}

fn io_error(path: &Path, source: io::Error) -> StagingError {
    StagingError::Io {
        path: path.to_path_buf(),
        source,
    }
}
