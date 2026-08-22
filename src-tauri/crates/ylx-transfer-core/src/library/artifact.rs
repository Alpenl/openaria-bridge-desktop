//! `ArtifactInspector` — issue #1, commit 32.
//!
//! # Why this module exists
//!
//! Before this module there were three independent, hand-rolled answers to
//! the question "what do we already have on disk for this file?":
//!
//! * `library::download::download_file` implicitly assumed "nothing" and
//!   always re-fetched, even when a fully verified file was already sitting
//!   at the target path (and on Windows the final `rename` over that
//!   pre-existing target fails outright).
//! * `library::download::recover_resume_offset` answered only for the
//!   `.part` file.
//! * `transfer::progress::disk_baseline` answered again, with its own
//!   "target exists at the right size ⇒ done" rule that cannot tell a
//!   correct file from a same-size file with the wrong contents.
//!
//! Three answers means recovery and the progress bar can disagree, and a
//! same-size/wrong-digest file can be reported as complete. This module is
//! the single judge: it looks at the **final file, the `.part` partial and
//! the journal/checkpoint together** and returns exactly one
//! [`ArtifactStatus`] per expected file. Both `download_file` (commit 32)
//! and `transfer::progress` (commit 33) consume that same evidence, so
//! there is no second opinion left to drift.
//!
//! # The four verdicts
//!
//! | verdict | meaning | recovery action |
//! |---|---|---|
//! | [`ArtifactStatus::Missing`] | nothing trustworthy on disk | download from byte 0 |
//! | [`ArtifactStatus::Partial`] | `durable_offset` bytes are durable | resume from `durable_offset` |
//! | [`ArtifactStatus::Verified`] | committed, exact size **and** digest | reuse — do not download |
//! | [`ArtifactStatus::Invalid`] | a committed file that is *wrong* | discard it and download again |
//!
//! `Partial`'s `durable_offset` is deliberately the *same* number
//! `recover_resume_offset` trusts — `min(.part length, journal
//! confirmed_offset)` — so "how much is done" and "where do we resume"
//! can never be two different numbers.
//!
//! # Cost
//!
//! Only a file that is present at exactly its expected size is hashed;
//! everything else is decided from `stat` alone. That is the minimum work
//! that can distinguish `Verified` from `Invalid`, and it is the whole
//! point of the commit: a size check alone cannot.

use std::path::{Path, PathBuf};
use std::{fs, io};

use super::download::{
    derive_target_path_for_file, journal_path, part_path, sha256_of_file, DownloadJournal, FilePlan,
};

/// One file a job expects to end up with, as described by the verified
/// publication: the opaque API id, the signed relative display path, the
/// expected size and (when the caller carries it) the expected digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedArtifact {
    pub file_id: String,
    /// Signed Pi `display_path`; `None` falls back to `file_id`, exactly
    /// as `derive_target_path_for_file` documents.
    pub target_relative_path: Option<String>,
    pub expected_size: u64,
    /// Lowercase hex SHA-256.
    ///
    /// `None` means *the caller does not know the digest* — not "any
    /// digest is fine". With no expected digest the inspector can only
    /// check size, so a size-matched target is reported [`Verified`] on
    /// size evidence alone (which is exactly the pre-inspector
    /// behaviour). Callers that have the digest — every production
    /// download path does, it is in the signed manifest — should always
    /// supply it; that is what makes a same-size/wrong-content file
    /// [`Invalid`] instead of silently "complete".
    ///
    /// [`Verified`]: ArtifactStatus::Verified
    /// [`Invalid`]: ArtifactStatus::Invalid
    pub expected_sha256_hex: Option<String>,
}

impl ExpectedArtifact {
    /// An expected file whose digest is known (the normal case).
    #[must_use]
    pub fn new(
        file_id: impl Into<String>,
        target_relative_path: Option<String>,
        expected_size: u64,
        expected_sha256_hex: impl Into<String>,
    ) -> Self {
        ExpectedArtifact {
            file_id: file_id.into(),
            target_relative_path,
            expected_size,
            expected_sha256_hex: Some(expected_sha256_hex.into()),
        }
    }

    /// An expected file whose digest the caller does not carry. See
    /// [`ExpectedArtifact::expected_sha256_hex`] for what that costs.
    #[must_use]
    pub fn without_digest(
        file_id: impl Into<String>,
        target_relative_path: Option<String>,
        expected_size: u64,
    ) -> Self {
        ExpectedArtifact {
            file_id: file_id.into(),
            target_relative_path,
            expected_size,
            expected_sha256_hex: None,
        }
    }
}

impl From<&FilePlan> for ExpectedArtifact {
    fn from(plan: &FilePlan) -> Self {
        ExpectedArtifact {
            file_id: plan.file_id.clone(),
            target_relative_path: plan.target_relative_path.clone(),
            expected_size: plan.expected_size,
            expected_sha256_hex: Some(plan.expected_sha256_hex.clone()),
        }
    }
}

/// Why a committed file cannot be trusted. Every variant names the exact
/// evidence that disqualified it, so a caller (or a log line) never has to
/// guess whether a file was short, corrupt, or unreadable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidReason {
    #[error("committed file is {actual} bytes, expected {expected}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("committed file's sha256 is {actual}, expected {expected}")]
    DigestMismatch { expected: String, actual: String },
    #[error("target path exists but is not a regular file")]
    NotARegularFile,
    #[error("target path could not be derived safely: {0}")]
    UnsafeTargetPath(String),
    #[error("could not read {path}: {message}")]
    Unreadable { path: PathBuf, message: String },
}

/// Exactly one verdict per expected file. See the module doc's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactStatus {
    /// Nothing trustworthy on disk: no committed file and no partial with
    /// a durable offset above zero.
    Missing,
    /// A `.part` file whose first `durable_offset` bytes are durable —
    /// `min(.part length, journal confirmed_offset)`, i.e. precisely
    /// `recover_resume_offset`'s trusted resume point.
    Partial { durable_offset: u64 },
    /// A committed file of exactly the expected size whose digest matches
    /// (or, when no digest was supplied, of exactly the expected size).
    Verified,
    /// A committed file that exists but must not be trusted.
    Invalid { reason: InvalidReason },
}

/// One file's verdict plus the facts a caller needs to act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactEvidence {
    pub file_id: String,
    pub expected_size: u64,
    /// The derived target path, or `None` when path derivation itself
    /// failed (`ArtifactStatus::Invalid { UnsafeTargetPath }`).
    pub target: Option<PathBuf>,
    pub status: ArtifactStatus,
}

impl ArtifactEvidence {
    /// Bytes this file contributes to "how much of the job is on disk".
    ///
    /// This is the single definition commit 33's progress accounting sums
    /// over: a verified file contributes its whole size, a partial
    /// contributes exactly the offset the next request would resume from,
    /// and anything missing or invalid contributes nothing — an invalid
    /// file is going to be re-downloaded from zero, so counting its bytes
    /// would be counting work that must be redone.
    #[must_use]
    pub fn durable_bytes(&self) -> u64 {
        match &self.status {
            ArtifactStatus::Verified => self.expected_size,
            ArtifactStatus::Partial { durable_offset } => (*durable_offset).min(self.expected_size),
            ArtifactStatus::Missing | ArtifactStatus::Invalid { .. } => 0,
        }
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self.status, ArtifactStatus::Verified)
    }

    /// Whether recovery must fetch (or keep fetching) this file. True for
    /// everything except [`ArtifactStatus::Verified`].
    #[must_use]
    pub fn needs_download(&self) -> bool {
        !self.is_verified()
    }
}

/// What a whole job's files look like on disk right now.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryPlan {
    pub evidence: Vec<ArtifactEvidence>,
}

impl RecoveryPlan {
    /// Files that are already `Verified` and must be reused as-is rather
    /// than downloaded again.
    pub fn reuse(&self) -> impl Iterator<Item = &ArtifactEvidence> {
        self.evidence.iter().filter(|e| e.is_verified())
    }

    /// Files recovery still has to fetch — missing, partial, or invalid.
    pub fn redownload(&self) -> impl Iterator<Item = &ArtifactEvidence> {
        self.evidence.iter().filter(|e| e.needs_download())
    }

    /// Sum of [`ArtifactEvidence::durable_bytes`] over every file.
    #[must_use]
    pub fn durable_bytes(&self) -> u64 {
        self.evidence
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.durable_bytes()))
    }

    #[must_use]
    pub fn verified_files(&self) -> u32 {
        self.evidence.iter().filter(|e| e.is_verified()).count() as u32
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.evidence
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.expected_size))
    }
}

/// The single judge of "what do we already have for this file?".
///
/// Scoped to one job's `(library_root, device_id, session_id)` so callers
/// cannot accidentally inspect one session's file against another's path.
#[derive(Debug, Clone)]
pub struct ArtifactInspector {
    library_root: PathBuf,
    device_id: String,
    session_id: String,
}

impl ArtifactInspector {
    #[must_use]
    pub fn new(
        library_root: impl Into<PathBuf>,
        device_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        ArtifactInspector {
            library_root: library_root.into(),
            device_id: device_id.into(),
            session_id: session_id.into(),
        }
    }

    /// Where this file would live. `None` when the ids/relative path are
    /// not safe (which is itself a verdict — see
    /// [`InvalidReason::UnsafeTargetPath`]).
    #[must_use]
    pub fn target_path(&self, expected: &ExpectedArtifact) -> Option<PathBuf> {
        derive_target_path_for_file(
            &self.library_root,
            &self.device_id,
            &self.session_id,
            &expected.file_id,
            expected.target_relative_path.as_deref(),
        )
        .ok()
    }

    /// Judge one expected file from the committed target, the `.part`
    /// partial and the journal together. Never fails: an unreadable or
    /// unsafe path is reported as [`ArtifactStatus::Invalid`], never as an
    /// error the caller has to invent a policy for.
    #[must_use]
    pub fn inspect(&self, expected: &ExpectedArtifact) -> ArtifactEvidence {
        let target = match derive_target_path_for_file(
            &self.library_root,
            &self.device_id,
            &self.session_id,
            &expected.file_id,
            expected.target_relative_path.as_deref(),
        ) {
            Ok(target) => target,
            Err(error) => {
                return ArtifactEvidence {
                    file_id: expected.file_id.clone(),
                    expected_size: expected.expected_size,
                    target: None,
                    status: ArtifactStatus::Invalid {
                        reason: InvalidReason::UnsafeTargetPath(error.to_string()),
                    },
                }
            }
        };

        let status = self.judge(&target, expected);
        ArtifactEvidence {
            file_id: expected.file_id.clone(),
            expected_size: expected.expected_size,
            target: Some(target),
            status,
        }
    }

    /// [`Self::inspect`] over a whole file plan.
    pub fn plan_recovery<'a, I>(&self, files: I) -> RecoveryPlan
    where
        I: IntoIterator<Item = &'a ExpectedArtifact>,
    {
        RecoveryPlan {
            evidence: files.into_iter().map(|f| self.inspect(f)).collect(),
        }
    }

    fn judge(&self, target: &Path, expected: &ExpectedArtifact) -> ArtifactStatus {
        // `symlink_metadata`, not `metadata`: a symlink sitting at the
        // target name is never a committed library file, however
        // convincing whatever it points at looks.
        match fs::symlink_metadata(target) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                ArtifactStatus::Invalid {
                    reason: InvalidReason::NotARegularFile,
                }
            }
            Ok(meta) => committed_verdict(target, meta.len(), expected),
            Err(e) if e.kind() == io::ErrorKind::NotFound => partial_verdict(target, expected),
            Err(e) => ArtifactStatus::Invalid {
                reason: InvalidReason::Unreadable {
                    path: target.to_path_buf(),
                    message: e.to_string(),
                },
            },
        }
    }
}

/// The verdict for a file that *is* sitting at the committed target name.
fn committed_verdict(
    target: &Path,
    actual_size: u64,
    expected: &ExpectedArtifact,
) -> ArtifactStatus {
    if actual_size != expected.expected_size {
        return ArtifactStatus::Invalid {
            reason: InvalidReason::SizeMismatch {
                expected: expected.expected_size,
                actual: actual_size,
            },
        };
    }
    let Some(expected_hex) = expected.expected_sha256_hex.as_deref() else {
        // Size-only evidence — see `ExpectedArtifact::expected_sha256_hex`.
        return ArtifactStatus::Verified;
    };
    match sha256_of_file(target) {
        Ok(actual) if actual == expected_hex.to_ascii_lowercase() => ArtifactStatus::Verified,
        Ok(actual) => ArtifactStatus::Invalid {
            reason: InvalidReason::DigestMismatch {
                expected: expected_hex.to_ascii_lowercase(),
                actual,
            },
        },
        Err(error) => ArtifactStatus::Invalid {
            reason: InvalidReason::Unreadable {
                path: target.to_path_buf(),
                message: error.to_string(),
            },
        },
    }
}

/// The verdict when no committed file exists: whatever the `.part` file
/// and its journal jointly prove, and nothing more.
fn partial_verdict(target: &Path, expected: &ExpectedArtifact) -> ArtifactStatus {
    let part_len = fs::metadata(part_path(target))
        .map(|m| m.len())
        .unwrap_or(0);
    let confirmed = DownloadJournal::read(&journal_path(target))
        .ok()
        .flatten()
        .map(|j| j.confirmed_offset)
        .unwrap_or(0);
    let durable_offset = part_len.min(confirmed).min(expected.expected_size);
    if durable_offset == 0 {
        ArtifactStatus::Missing
    } else {
        ArtifactStatus::Partial { durable_offset }
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    // -----------------------------------------------------------------
    // Shared fixtures — every test below judges files laid out by these
    // three helpers, so "what the inspector sees" is described in one
    // place instead of re-hand-rolled per test.
    // -----------------------------------------------------------------

    const DEVICE: &str = "dev-1";
    const SESSION: &str = "sess-1";

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    struct Fixture {
        root: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                root: tempdir().expect("tempdir"),
            }
        }

        fn inspector(&self) -> ArtifactInspector {
            ArtifactInspector::new(self.root.path(), DEVICE, SESSION)
        }

        fn expected(&self, file_id: &str, contents: &[u8]) -> ExpectedArtifact {
            ExpectedArtifact::new(file_id, None, contents.len() as u64, sha256_hex(contents))
        }

        fn target(&self, file_id: &str) -> PathBuf {
            derive_target_path_for_file(self.root.path(), DEVICE, SESSION, file_id, None)
                .expect("safe target")
        }

        /// A file that finished: bytes renamed onto the committed name.
        fn commit_target(&self, file_id: &str, contents: &[u8]) -> PathBuf {
            let target = self.target(file_id);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(&target, contents).unwrap();
            target
        }

        /// A crashed-mid-download file: `.part` bytes plus a journal
        /// confirming `confirmed` of them.
        fn seed_partial(
            &self,
            file_id: &str,
            on_disk: &[u8],
            confirmed: u64,
            expected_total: &[u8],
        ) -> PathBuf {
            let target = self.target(file_id);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(part_path(&target), on_disk).unwrap();
            DownloadJournal::write(
                &journal_path(&target),
                &DownloadJournal {
                    confirmed_offset: confirmed,
                    expected_size: expected_total.len() as u64,
                    expected_sha256_hex: sha256_hex(expected_total),
                    etag: Some("etag-1".to_string()),
                },
            )
            .unwrap();
            target
        }
    }

    // -----------------------------------------------------------------
    // The four verdicts
    // -----------------------------------------------------------------

    #[test]
    fn nothing_on_disk_is_missing() {
        let fx = Fixture::new();
        let evidence = fx.inspector().inspect(&fx.expected("f1", b"payload"));
        assert_eq!(evidence.status, ArtifactStatus::Missing);
        assert_eq!(evidence.durable_bytes(), 0);
        assert!(evidence.needs_download());
    }

    #[test]
    fn multiple_partials_each_report_their_own_durable_offset() {
        let fx = Fixture::new();
        let full = vec![7u8; 100];
        // f1: 80 bytes written, only 64 checkpointed -> 64 is durable.
        fx.seed_partial("f1", &full[..80], 64, &full);
        // f2: 30 bytes written and all 30 checkpointed.
        fx.seed_partial("f2", &full[..30], 30, &full);
        // f3: bytes on disk but no journal at all -> nothing is durable.
        let f3 = fx.target("f3");
        fs::create_dir_all(f3.parent().unwrap()).unwrap();
        fs::write(part_path(&f3), &full[..50]).unwrap();

        let inspector = fx.inspector();
        let files = vec![
            fx.expected("f1", &full),
            fx.expected("f2", &full),
            fx.expected("f3", &full),
        ];
        let plan = inspector.plan_recovery(&files);

        assert_eq!(
            plan.evidence
                .iter()
                .map(|e| e.status.clone())
                .collect::<Vec<_>>(),
            vec![
                ArtifactStatus::Partial { durable_offset: 64 },
                ArtifactStatus::Partial { durable_offset: 30 },
                ArtifactStatus::Missing,
            ]
        );
        assert_eq!(plan.durable_bytes(), 94);
        assert_eq!(plan.verified_files(), 0);
        assert_eq!(plan.redownload().count(), 3);
    }

    #[test]
    fn a_complete_committed_target_is_verified_and_reused() {
        let fx = Fixture::new();
        let data = b"a whole, correct file".to_vec();
        fx.commit_target("f1", &data);

        let evidence = fx.inspector().inspect(&fx.expected("f1", &data));
        assert_eq!(evidence.status, ArtifactStatus::Verified);
        assert_eq!(evidence.durable_bytes(), data.len() as u64);
        assert!(!evidence.needs_download(), "a verified file must be reused");
    }

    #[test]
    fn a_right_sized_target_with_the_wrong_digest_is_invalid_not_verified() {
        let fx = Fixture::new();
        let real = b"the genuine contents of this file".to_vec();
        // Same length, different bytes: a size-only check calls this done.
        let corrupt: Vec<u8> = real.iter().map(|b| b ^ 0x20).collect();
        assert_eq!(corrupt.len(), real.len());
        fx.commit_target("f1", &corrupt);

        let evidence = fx.inspector().inspect(&fx.expected("f1", &real));
        assert!(
            matches!(
                &evidence.status,
                ArtifactStatus::Invalid {
                    reason: InvalidReason::DigestMismatch { .. }
                }
            ),
            "expected a digest mismatch, got {:?}",
            evidence.status
        );
        assert_eq!(
            evidence.durable_bytes(),
            0,
            "a file that must be re-downloaded contributes no progress"
        );
        assert!(evidence.needs_download());
    }

    #[test]
    fn a_short_committed_target_is_invalid_with_the_exact_sizes() {
        let fx = Fixture::new();
        let real = b"0123456789".to_vec();
        fx.commit_target("f1", &real[..4]);

        let evidence = fx.inspector().inspect(&fx.expected("f1", &real));
        assert_eq!(
            evidence.status,
            ArtifactStatus::Invalid {
                reason: InvalidReason::SizeMismatch {
                    expected: 10,
                    actual: 4
                }
            }
        );
    }

    // -----------------------------------------------------------------
    // Crash points
    // -----------------------------------------------------------------

    #[test]
    fn crash_before_rename_is_a_full_length_partial_and_after_rename_is_verified() {
        let fx = Fixture::new();
        let data = b"every byte of this file made it to the .part".to_vec();

        // Crash *before* the rename: the `.part` holds the whole file and
        // the journal confirms it, but nothing is committed yet.
        fx.seed_partial("before", &data, data.len() as u64, &data);
        let before = fx.inspector().inspect(&fx.expected("before", &data));
        assert_eq!(
            before.status,
            ArtifactStatus::Partial {
                durable_offset: data.len() as u64
            },
            "an un-renamed .part is never 'verified' — nothing has been hash-checked and committed"
        );
        assert_eq!(before.durable_bytes(), data.len() as u64);

        // Crash *after* the rename but before the journal was cleaned up:
        // the committed file is the truth, the leftover journal is noise.
        let target = fx.commit_target("after", &data);
        DownloadJournal::write(
            &journal_path(&target),
            &DownloadJournal {
                confirmed_offset: 3,
                expected_size: data.len() as u64,
                expected_sha256_hex: sha256_hex(&data),
                etag: Some("etag-1".to_string()),
            },
        )
        .unwrap();
        let after = fx.inspector().inspect(&fx.expected("after", &data));
        assert_eq!(after.status, ArtifactStatus::Verified);
        assert_eq!(after.durable_bytes(), data.len() as u64);
    }

    #[test]
    fn a_pre_existing_target_is_judged_not_assumed_the_windows_rename_case() {
        // On Windows `rename` onto an existing target fails, so a leftover
        // target file is a real recovery input, not a theoretical one.
        // Expressed here as a pre-existing target file so it runs
        // everywhere.
        let fx = Fixture::new();
        let wanted = b"what this job is supposed to produce".to_vec();
        let leftover = b"an older, different file at the same name".to_vec();
        assert_ne!(leftover.len(), wanted.len());

        fx.commit_target("f1", &leftover);
        let stale = fx.inspector().inspect(&fx.expected("f1", &wanted));
        assert!(
            matches!(
                stale.status,
                ArtifactStatus::Invalid {
                    reason: InvalidReason::SizeMismatch { .. }
                }
            ),
            "a pre-existing wrong target must be Invalid (re-download), got {:?}",
            stale.status
        );

        // The same name holding the *right* file is the other half of the
        // case: it must be reused, not re-downloaded and re-renamed.
        fx.commit_target("f1", &wanted);
        let good = fx.inspector().inspect(&fx.expected("f1", &wanted));
        assert_eq!(good.status, ArtifactStatus::Verified);
    }

    // -----------------------------------------------------------------
    // Degenerate inputs
    // -----------------------------------------------------------------

    #[test]
    fn an_unsafe_file_id_is_invalid_rather_than_a_panic_or_a_silent_skip() {
        let fx = Fixture::new();
        let evidence = fx.inspector().inspect(&ExpectedArtifact::new(
            "../escape",
            None,
            10,
            "0".repeat(64),
        ));
        assert!(matches!(
            evidence.status,
            ArtifactStatus::Invalid {
                reason: InvalidReason::UnsafeTargetPath(_)
            }
        ));
        assert_eq!(evidence.target, None);
        assert_eq!(evidence.durable_bytes(), 0);
    }

    #[test]
    fn a_directory_at_the_target_name_is_invalid() {
        let fx = Fixture::new();
        let target = fx.target("f1");
        fs::create_dir_all(&target).unwrap();

        let evidence = fx.inspector().inspect(&fx.expected("f1", b"payload"));
        assert_eq!(
            evidence.status,
            ArtifactStatus::Invalid {
                reason: InvalidReason::NotARegularFile
            }
        );
    }

    #[test]
    fn without_a_digest_the_inspector_falls_back_to_size_only_evidence() {
        let fx = Fixture::new();
        let real = b"0123456789".to_vec();
        let corrupt: Vec<u8> = real.iter().map(|b| b ^ 0x20).collect();
        fx.commit_target("f1", &corrupt);

        let evidence = fx
            .inspector()
            .inspect(&ExpectedArtifact::without_digest("f1", None, 10));
        assert_eq!(
            evidence.status,
            ArtifactStatus::Verified,
            "with no expected digest there is nothing to compare against"
        );
    }

    #[test]
    fn the_signed_relative_display_path_is_followed() {
        let fx = Fixture::new();
        let data = b"nested payload".to_vec();
        let target = fx
            .root
            .path()
            .join(DEVICE)
            .join(SESSION)
            .join("video")
            .join("left_00000.mp4");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, &data).unwrap();

        let evidence = fx.inspector().inspect(&ExpectedArtifact::new(
            "opaque-file-id",
            Some("video/left_00000.mp4".to_string()),
            data.len() as u64,
            sha256_hex(&data),
        ));
        assert_eq!(evidence.status, ArtifactStatus::Verified);
        assert_eq!(evidence.target.as_deref(), Some(target.as_path()));
    }

    #[test]
    fn a_recovery_plan_splits_reuse_from_redownload() {
        let fx = Fixture::new();
        let data = vec![9u8; 40];
        fx.commit_target("done", &data);
        fx.seed_partial("half", &data[..20], 20, &data);
        let corrupt: Vec<u8> = data.iter().map(|b| b ^ 0xff).collect();
        fx.commit_target("bad", &corrupt);
        // "gone" has nothing on disk.

        let files = vec![
            fx.expected("done", &data),
            fx.expected("half", &data),
            fx.expected("bad", &data),
            fx.expected("gone", &data),
        ];
        let plan = fx.inspector().plan_recovery(&files);

        assert_eq!(
            plan.reuse().map(|e| e.file_id.as_str()).collect::<Vec<_>>(),
            vec!["done"]
        );
        assert_eq!(
            plan.redownload()
                .map(|e| e.file_id.as_str())
                .collect::<Vec<_>>(),
            vec!["half", "bad", "gone"]
        );
        assert_eq!(plan.total_bytes(), 160);
        assert_eq!(plan.durable_bytes(), 60, "40 verified + 20 durable partial");
        assert_eq!(plan.verified_files(), 1);
    }
}
