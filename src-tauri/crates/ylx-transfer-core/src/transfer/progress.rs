//! Byte-level transfer progress — the second, independent channel next to
//! [`super::TransferJobState`].
//!
//! # Why this is not part of `TransferJobState`
//!
//! `TransferJobState` is plan 5.4's frozen, serde-tagged job enum (the
//! front end mirrors its exact shape); adding byte counters to it would
//! change that wire shape for every consumer. Progress is therefore a
//! *separate* read-only channel: the coordinator owns one
//! [`JobProgressTracker`] per job and exposes an immutable
//! [`JobProgress`] snapshot through
//! `TransferCoordinator::job_progress()`. Nothing in the state enum
//! changed.
//!
//! # What `transferred_bytes` actually means
//!
//! "Bytes that are on local disk for this job" — a **sum over the job's
//! files of the per-file evidence `library::artifact::ArtifactInspector`
//! produces**, not an independent counter that can drift away from it
//! (issue #1, commit 33):
//!
//! 1. **Verified files** contribute their full `expected_size`. "Verified"
//!    is the inspector's verdict: present at exactly the expected size
//!    *and* matching the expected SHA-256. A file whose size is right but
//!    whose digest is wrong is `Invalid`, contributes **zero**, and is
//!    re-downloaded — it must never read as complete.
//! 2. **Every partial** contributes its `durable_offset` — `min(.part
//!    length, journal confirmed_offset)`, exactly the offset
//!    `recover_resume_offset` will resume from, so "how much is done" and
//!    "where do we restart" are one number, not two.
//! 3. **The file currently in flight** contributes the offset of the
//!    response body being consumed: the resume offset the download engine
//!    itself requested plus every byte read since. A `200` response is
//!    counted from 0, because `download_file` treats `200` as "restart at
//!    byte 0, never append" regardless of what was requested.
//!
//! Items 1 and 2 are the *baseline* ([`disk_baseline`] /
//! [`DiskBaseline::from_evidence`]), computed when the job enters memory
//! (`enqueue` or `recover_on_startup`) so a recovered job does not start
//! crawling from zero; item 3 is the live counter the worker updates.
//!
//! # Substituting a durable ledger later
//!
//! The baseline is built through [`FileEvidenceSource`], which yields
//! `ArtifactEvidence` values. Today the only implementation
//! ([`DiskEvidence`]) derives them by inspecting the filesystem. When the
//! durable per-file ledger lands, a ledger-backed `FileEvidenceSource` can
//! be substituted with no change to the accounting above — the arithmetic
//! lives in [`DiskBaseline::from_evidence`], which only ever asks each
//! evidence item for [`ArtifactEvidence::durable_bytes`].
//!
//! # Monotonicity
//!
//! A job's reported `transferred_bytes` never decreases (a retry is a
//! brand-new `JobId` with its own tracker, so it legitimately starts
//! over). The tracker keeps a high-water mark: when a resume baseline
//! lands *below* a previously observed value — which happens legitimately,
//! because `download_file`'s sidecar journal is only checkpointed every
//! `JOURNAL_CHECKPOINT_INTERVAL` bytes, so up to that many already-written
//! bytes are deliberately distrusted and re-fetched after an interrupt —
//! the reported value plateaus at the high-water mark while those bytes
//! are re-fetched instead of visibly going backwards. Bytes are never
//! double-counted: the plateau is exactly the re-fetch window.
//!
//! `transferred_bytes` is also clamped to `total_bytes`, so a misbehaving
//! source that streams more than the manifest's `expected_size` (which
//! `download_file` rejects anyway) can never report >100%.

use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::library::artifact::{
    ArtifactEvidence, ArtifactInspector, ArtifactStatus, ExpectedArtifact,
};

/// An immutable byte-level progress snapshot for one transfer job.
///
/// `total_bytes` and `files_total` are fixed for the lifetime of a job
/// (they come from the verified publication payload's file list);
/// `transferred_bytes` and `files_done` only ever grow. A successfully
/// completed job always reports `transferred_bytes == total_bytes` and
/// `files_done == files_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct JobProgress {
    /// Sum of every planned file's `expected_size`.
    pub total_bytes: u64,
    /// Bytes durably on local disk for this job, including any resume
    /// baseline. Monotonically non-decreasing; never exceeds
    /// `total_bytes`.
    pub transferred_bytes: u64,
    /// Number of files this job must move.
    pub files_total: u32,
    /// Number of files fully downloaded, size+hash verified, and
    /// atomically committed.
    pub files_done: u32,
}

/// The mutable, thread-safe counter behind [`JobProgress`]. One per job,
/// shared between the coordinator (which reads snapshots and records file
/// completions) and the worker thread's `queue::TrackingSource` (which
/// reports the in-flight file's offset as bytes arrive).
#[derive(Debug)]
pub struct JobProgressTracker {
    total_bytes: u64,
    files_total: u32,
    /// Sum of `expected_size` over files proven complete.
    completed_bytes: AtomicU64,
    files_done: AtomicU32,
    /// Offset within the file currently being downloaded (0 when no file
    /// is in flight).
    current_file_bytes: AtomicU64,
    /// High-water mark — see the module doc's "Monotonicity" section.
    peak_transferred: AtomicU64,
}

impl JobProgressTracker {
    /// A tracker for a job with nothing on disk yet.
    #[must_use]
    pub fn new(total_bytes: u64, files_total: u32) -> Self {
        JobProgressTracker {
            total_bytes,
            files_total,
            completed_bytes: AtomicU64::new(0),
            files_done: AtomicU32::new(0),
            current_file_bytes: AtomicU64::new(0),
            peak_transferred: AtomicU64::new(0),
        }
    }

    /// A tracker seeded from what is already on disk (see
    /// [`disk_baseline`]). `partial_bytes` is folded straight into the
    /// high-water mark rather than into `completed_bytes`, because those
    /// bytes belong to files that are *not* finished — they must not be
    /// counted twice once the in-flight counter picks the same file back
    /// up.
    #[must_use]
    pub fn with_baseline(total_bytes: u64, files_total: u32, baseline: DiskBaseline) -> Self {
        let tracker = JobProgressTracker::new(total_bytes, files_total);
        tracker
            .completed_bytes
            .store(baseline.completed_bytes, Ordering::SeqCst);
        tracker
            .files_done
            .store(baseline.files_done, Ordering::SeqCst);
        tracker.peak_transferred.store(
            (baseline.completed_bytes + baseline.partial_bytes).min(total_bytes),
            Ordering::SeqCst,
        );
        tracker
    }

    /// A tracker whose totals *and* baseline both come from one
    /// [`FileEvidenceSource`] read (issue #1, commit 33).
    ///
    /// Preferred over [`JobProgressTracker::with_baseline`] because the
    /// denominator (`total_bytes`, `files_total`) and the numerator cannot
    /// be assembled from two different views of the job: they are folded
    /// from the same evidence list in one pass.
    #[must_use]
    pub fn from_evidence_source(source: &dyn FileEvidenceSource) -> Self {
        let evidence = source.file_evidence();
        let total_bytes = evidence
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.expected_size));
        let files_total = evidence.len() as u32;
        JobProgressTracker::with_baseline(
            total_bytes,
            files_total,
            DiskBaseline::from_evidence(evidence.iter()),
        )
    }

    /// Report the absolute offset reached within the file currently being
    /// downloaded. Called with the requested resume offset when a response
    /// opens and after every chunk read from its body.
    pub fn set_current_file_offset(&self, offset: u64) {
        self.current_file_bytes.store(offset, Ordering::SeqCst);
        self.bump_peak();
    }

    /// One file finished: verified and atomically committed by
    /// `download_file`. Clears the in-flight counter *before* adding the
    /// file's full size, so a concurrent snapshot can only ever read low
    /// (and the high-water mark hides even that), never double-count.
    pub fn file_completed(&self, expected_size: u64) {
        self.current_file_bytes.store(0, Ordering::SeqCst);
        self.completed_bytes
            .fetch_add(expected_size, Ordering::SeqCst);
        self.files_done.fetch_add(1, Ordering::SeqCst);
        self.bump_peak();
    }

    fn raw_transferred(&self) -> u64 {
        self.completed_bytes
            .load(Ordering::SeqCst)
            .saturating_add(self.current_file_bytes.load(Ordering::SeqCst))
            .min(self.total_bytes)
    }

    fn bump_peak(&self) {
        self.peak_transferred
            .fetch_max(self.raw_transferred(), Ordering::SeqCst);
    }

    /// The current immutable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> JobProgress {
        JobProgress {
            total_bytes: self.total_bytes,
            transferred_bytes: self
                .peak_transferred
                .load(Ordering::SeqCst)
                .max(self.raw_transferred()),
            files_total: self.files_total,
            files_done: self.files_done.load(Ordering::SeqCst).min(self.files_total),
        }
    }
}

/// What a job's per-file evidence adds up to — see
/// [`DiskBaseline::from_evidence`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskBaseline {
    /// Sum of `expected_size` over files the inspector judged `Verified`.
    pub completed_bytes: u64,
    pub files_done: u32,
    /// Sum of every partial's `durable_offset`.
    pub partial_bytes: u64,
}

impl DiskBaseline {
    /// Fold per-file evidence into a job-level baseline. This is the only
    /// arithmetic in the progress path, and it consults nothing but each
    /// item's own verdict — so whichever [`FileEvidenceSource`] produced
    /// them (disk today, the durable ledger later) the totals mean the
    /// same thing.
    ///
    /// A `Verified` file counts in full; a `Partial` counts exactly its
    /// durable offset; `Missing` and `Invalid` count for nothing — an
    /// invalid file (right size, wrong digest) is about to be
    /// re-downloaded from zero, so counting it would report work that
    /// still has to happen.
    #[must_use]
    pub fn from_evidence<'a, I>(evidence: I) -> Self
    where
        I: IntoIterator<Item = &'a ArtifactEvidence>,
    {
        let mut baseline = DiskBaseline::default();
        for item in evidence {
            match item.status {
                ArtifactStatus::Verified => {
                    baseline.completed_bytes = baseline
                        .completed_bytes
                        .saturating_add(item.durable_bytes());
                    baseline.files_done += 1;
                }
                ArtifactStatus::Partial { .. } => {
                    baseline.partial_bytes =
                        baseline.partial_bytes.saturating_add(item.durable_bytes());
                }
                ArtifactStatus::Missing | ArtifactStatus::Invalid { .. } => {}
            }
        }
        baseline
    }

    /// Bytes on disk for the job, ignoring anything currently in flight.
    #[must_use]
    pub fn durable_bytes(&self) -> u64 {
        self.completed_bytes.saturating_add(self.partial_bytes)
    }
}

/// Where a job's per-file evidence comes from.
///
/// Progress must never be an independent counter, so this is the seam the
/// accounting is built on. [`DiskEvidence`] is the implementation today
/// (it asks `ArtifactInspector`); a ledger-backed implementation can
/// replace it without touching [`DiskBaseline::from_evidence`] or
/// [`JobProgressTracker`].
pub trait FileEvidenceSource {
    fn file_evidence(&self) -> Vec<ArtifactEvidence>;
}

/// The filesystem-backed [`FileEvidenceSource`]: one `ArtifactInspector`
/// pass over the job's expected files.
#[derive(Debug, Clone)]
pub struct DiskEvidence {
    inspector: ArtifactInspector,
    files: Vec<ExpectedArtifact>,
}

impl DiskEvidence {
    #[must_use]
    pub fn new(
        library_root: &Path,
        device_id: &str,
        session_id: &str,
        files: Vec<ExpectedArtifact>,
    ) -> Self {
        DiskEvidence {
            inspector: ArtifactInspector::new(library_root, device_id, session_id),
            files,
        }
    }
}

impl FileEvidenceSource for DiskEvidence {
    fn file_evidence(&self) -> Vec<ArtifactEvidence> {
        self.inspector.plan_recovery(self.files.iter()).evidence
    }
}

/// Derive what a job has already transferred — used to seed a tracker at
/// `enqueue` and, more importantly, at `recover_on_startup` (requirement:
/// a recovered job must not restart its progress bar at zero).
///
/// A thin wrapper over [`DiskEvidence`] + [`DiskBaseline::from_evidence`],
/// kept for callers that hold `(file_id, display_path, expected_size)`
/// tuples.
///
/// # Digest-free evidence
///
/// This overload carries **no expected digest**, so the inspector can only
/// check size and a same-size/wrong-content file still reads as complete.
/// Callers that hold the expected SHA-256 (every production download job
/// does — it is in the signed manifest) should build
/// [`ExpectedArtifact`]s and use [`baseline_from_source`] instead, which
/// is what makes a corrupt file count as zero rather than as done.
///
/// Never errors: an unreadable, absent, or unsafe path simply contributes
/// nothing.
pub fn disk_baseline<'a, I>(
    library_root: &Path,
    device_id: &str,
    session_id: &str,
    files: I,
) -> DiskBaseline
where
    I: IntoIterator<Item = (&'a str, Option<&'a str>, u64)>,
{
    let expected: Vec<ExpectedArtifact> = files
        .into_iter()
        .map(|(file_id, target_relative_path, expected_size)| {
            ExpectedArtifact::without_digest(
                file_id,
                target_relative_path.map(str::to_string),
                expected_size,
            )
        })
        .collect();
    baseline_from_source(&DiskEvidence::new(
        library_root,
        device_id,
        session_id,
        expected,
    ))
}

/// [`DiskBaseline::from_evidence`] over whatever a [`FileEvidenceSource`]
/// reports. The substitution point for a future ledger-backed source.
#[must_use]
pub fn baseline_from_source(source: &dyn FileEvidenceSource) -> DiskBaseline {
    DiskBaseline::from_evidence(source.file_evidence().iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::download::{journal_path, part_path, DownloadJournal};
    use std::fs;
    use tempfile::tempdir;

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    #[test]
    fn fresh_tracker_reports_zero_transferred_and_the_planned_totals() {
        let tracker = JobProgressTracker::new(300, 3);
        assert_eq!(
            tracker.snapshot(),
            JobProgress {
                total_bytes: 300,
                transferred_bytes: 0,
                files_total: 3,
                files_done: 0,
            }
        );
    }

    #[test]
    fn multi_file_accumulation_never_drops_a_finished_file() {
        let tracker = JobProgressTracker::new(300, 3);
        tracker.set_current_file_offset(50);
        assert_eq!(tracker.snapshot().transferred_bytes, 50);
        tracker.file_completed(100);
        assert_eq!(tracker.snapshot().transferred_bytes, 100);

        // Second file starts at 0 — the first file's 100 bytes stay.
        tracker.set_current_file_offset(0);
        assert_eq!(tracker.snapshot().transferred_bytes, 100);
        tracker.set_current_file_offset(75);
        assert_eq!(tracker.snapshot().transferred_bytes, 175);
        tracker.file_completed(100);
        tracker.file_completed(100);
        assert_eq!(
            tracker.snapshot(),
            JobProgress {
                total_bytes: 300,
                transferred_bytes: 300,
                files_total: 3,
                files_done: 3,
            }
        );
    }

    #[test]
    fn a_resume_baseline_below_the_high_water_mark_plateaus_instead_of_regressing() {
        let tracker = JobProgressTracker::new(1000, 1);
        tracker.set_current_file_offset(400);
        assert_eq!(tracker.snapshot().transferred_bytes, 400);

        // Interrupted; the journal had only checkpointed 256 bytes, so
        // `download_file` resumes from there.
        tracker.set_current_file_offset(256);
        assert_eq!(
            tracker.snapshot().transferred_bytes,
            400,
            "reported progress must not go backwards over a journal-lag resume"
        );
        tracker.set_current_file_offset(500);
        assert_eq!(tracker.snapshot().transferred_bytes, 500);
    }

    #[test]
    fn a_full_restart_from_zero_does_not_reset_reported_progress() {
        let tracker = JobProgressTracker::new(1000, 1);
        tracker.set_current_file_offset(600);
        // ETag changed / 200 fallback: the engine restarts at byte 0.
        tracker.set_current_file_offset(0);
        assert_eq!(tracker.snapshot().transferred_bytes, 600);
        tracker.file_completed(1000);
        assert_eq!(tracker.snapshot().transferred_bytes, 1000);
    }

    #[test]
    fn transferred_bytes_is_clamped_to_total_bytes() {
        let tracker = JobProgressTracker::new(100, 1);
        tracker.set_current_file_offset(u64::MAX);
        assert_eq!(tracker.snapshot().transferred_bytes, 100);
    }

    #[test]
    fn baseline_seeds_completed_and_partial_bytes_without_double_counting() {
        let baseline = DiskBaseline {
            completed_bytes: 100,
            files_done: 1,
            partial_bytes: 40,
        };
        let tracker = JobProgressTracker::with_baseline(300, 3, baseline);
        assert_eq!(
            tracker.snapshot(),
            JobProgress {
                total_bytes: 300,
                transferred_bytes: 140,
                files_total: 3,
                files_done: 1,
            }
        );
        // Picking that partial file back up must not add its 40 bytes a
        // second time.
        tracker.set_current_file_offset(40);
        assert_eq!(tracker.snapshot().transferred_bytes, 140);
        tracker.set_current_file_offset(60);
        assert_eq!(tracker.snapshot().transferred_bytes, 160);
    }

    #[test]
    fn disk_baseline_counts_committed_files_and_trusted_partials_only() {
        let root = tempdir().unwrap();
        let session_dir = root.path().join("dev-1").join("sess-1");
        fs::create_dir_all(&session_dir).unwrap();

        // f1: fully committed (exact expected size).
        fs::write(session_dir.join("f1"), vec![1u8; 100]).unwrap();
        // f2: partial — 80 bytes on disk, journal only confirms 64.
        let f2 = session_dir.join("f2");
        fs::write(part_path(&f2), vec![2u8; 80]).unwrap();
        DownloadJournal::write(
            &journal_path(&f2),
            &DownloadJournal {
                confirmed_offset: 64,
                expected_size: 100,
                expected_sha256_hex: "0".repeat(64),
                etag: None,
            },
        )
        .unwrap();
        // f3: partial with no journal at all -> contributes nothing.
        fs::write(part_path(&session_dir.join("f3")), vec![3u8; 50]).unwrap();
        // f4: nothing on disk at all.

        let baseline = disk_baseline(
            root.path(),
            "dev-1",
            "sess-1",
            [
                ("f1", None, 100u64),
                ("f2", None, 100),
                ("f3", None, 100),
                ("f4", None, 100),
            ],
        );
        assert_eq!(
            baseline,
            DiskBaseline {
                completed_bytes: 100,
                files_done: 1,
                partial_bytes: 64,
            }
        );
    }

    #[test]
    fn disk_baseline_ignores_a_wrong_sized_target_and_unsafe_ids() {
        let root = tempdir().unwrap();
        let session_dir = root.path().join("dev-1").join("sess-1");
        fs::create_dir_all(&session_dir).unwrap();
        // Truncated/short target file is NOT proof of a committed file.
        fs::write(session_dir.join("f1"), vec![1u8; 99]).unwrap();

        let baseline = disk_baseline(
            root.path(),
            "dev-1",
            "sess-1",
            [("f1", None, 100u64), ("../escape", None, 100)],
        );
        assert_eq!(baseline, DiskBaseline::default());
    }

    #[test]
    fn disk_baseline_follows_the_persisted_pi_relative_path() {
        let root = tempdir().unwrap();
        let target = root
            .path()
            .join("dev-1")
            .join("sess-1")
            .join("video")
            .join("left_00000.mp4");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, vec![1u8; 100]).unwrap();

        let baseline = disk_baseline(
            root.path(),
            "dev-1",
            "sess-1",
            [("opaque-file-id", Some("video/left_00000.mp4"), 100)],
        );
        assert_eq!(
            baseline,
            DiskBaseline {
                completed_bytes: 100,
                files_done: 1,
                partial_bytes: 0,
            }
        );
    }

    // -----------------------------------------------------------------
    // Progress from per-file evidence (issue #1, commit 33)
    // -----------------------------------------------------------------

    /// Lay out one job's files on disk: `done` is committed and correct,
    /// `corrupt` is committed at exactly the right size with the wrong
    /// bytes, `half-a`/`half-b` are two independent partials, and `gone`
    /// has nothing at all.
    fn seed_mixed_job(root: &Path) -> Vec<ExpectedArtifact> {
        let session_dir = root.join("dev-1").join("sess-1");
        fs::create_dir_all(&session_dir).unwrap();
        let payload = vec![1u8; 100];
        let corrupt: Vec<u8> = payload.iter().map(|b| b ^ 0xff).collect();

        fs::write(session_dir.join("done"), &payload).unwrap();
        fs::write(session_dir.join("corrupt"), &corrupt).unwrap();

        for (name, on_disk, confirmed) in [("half-a", 80usize, 64u64), ("half-b", 40, 40)] {
            let target = session_dir.join(name);
            fs::write(part_path(&target), &payload[..on_disk]).unwrap();
            DownloadJournal::write(
                &journal_path(&target),
                &DownloadJournal {
                    confirmed_offset: confirmed,
                    expected_size: 100,
                    expected_sha256_hex: sha256_hex(&payload),
                    etag: Some("etag-1".to_string()),
                },
            )
            .unwrap();
        }

        ["done", "corrupt", "half-a", "half-b", "gone"]
            .into_iter()
            .map(|id| ExpectedArtifact::new(id, None, 100, sha256_hex(&payload)))
            .collect()
    }

    #[test]
    fn a_same_size_file_with_the_wrong_digest_is_not_counted_as_complete() {
        let root = tempdir().unwrap();
        let files = seed_mixed_job(root.path());
        let source = DiskEvidence::new(root.path(), "dev-1", "sess-1", files);

        let baseline = baseline_from_source(&source);
        assert_eq!(
            baseline,
            DiskBaseline {
                // Only `done` — `corrupt` is the same size but the wrong
                // bytes, and a size-only rule would have counted it.
                completed_bytes: 100,
                files_done: 1,
                partial_bytes: 104, // 64 + 40, each partial in its own right
            }
        );
        assert_eq!(baseline.durable_bytes(), 204);
    }

    #[test]
    fn a_tracker_built_from_evidence_sums_verified_partials_and_the_current_file() {
        let root = tempdir().unwrap();
        let files = seed_mixed_job(root.path());
        let source = DiskEvidence::new(root.path(), "dev-1", "sess-1", files);

        let tracker = JobProgressTracker::from_evidence_source(&source);
        assert_eq!(
            tracker.snapshot(),
            JobProgress {
                total_bytes: 500,
                transferred_bytes: 204,
                files_total: 5,
                // The corrupt file must not inflate the completed count.
                files_done: 1,
            }
        );

        // Picking `half-a` back up at its durable offset must not add the
        // same 64 bytes twice; overtaking the whole baseline plateau must
        // show through.
        tracker.set_current_file_offset(64);
        assert_eq!(tracker.snapshot().transferred_bytes, 204);
        tracker.set_current_file_offset(100);
        assert_eq!(tracker.snapshot().transferred_bytes, 204);
        tracker.file_completed(100);
        assert_eq!(tracker.snapshot().transferred_bytes, 204);
        tracker.set_current_file_offset(40);
        assert_eq!(tracker.snapshot().transferred_bytes, 240);
    }

    #[test]
    fn any_file_evidence_source_can_back_the_baseline() {
        // Stand-in for the durable per-file ledger: no filesystem at all.
        struct LedgerEvidence(Vec<ArtifactEvidence>);
        impl FileEvidenceSource for LedgerEvidence {
            fn file_evidence(&self) -> Vec<ArtifactEvidence> {
                self.0.clone()
            }
        }

        let ledger = LedgerEvidence(vec![
            ArtifactEvidence {
                file_id: "done".to_string(),
                expected_size: 100,
                target: None,
                status: ArtifactStatus::Verified,
            },
            ArtifactEvidence {
                file_id: "half".to_string(),
                expected_size: 100,
                target: None,
                status: ArtifactStatus::Partial { durable_offset: 25 },
            },
            ArtifactEvidence {
                file_id: "bad".to_string(),
                expected_size: 100,
                target: None,
                status: ArtifactStatus::Invalid {
                    reason: crate::library::artifact::InvalidReason::DigestMismatch {
                        expected: "a".repeat(64),
                        actual: "b".repeat(64),
                    },
                },
            },
        ]);

        assert_eq!(
            baseline_from_source(&ledger),
            DiskBaseline {
                completed_bytes: 100,
                files_done: 1,
                partial_bytes: 25,
            }
        );
        assert_eq!(
            JobProgressTracker::from_evidence_source(&ledger).snapshot(),
            JobProgress {
                total_bytes: 300,
                transferred_bytes: 125,
                files_total: 3,
                files_done: 1,
            }
        );
    }
}
