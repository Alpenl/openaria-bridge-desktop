//! Deterministic scale fixture and trace harness for Score #32.
//!
//! This module is compiled only through the explicit
//! `performance-benchmark` feature. It is not part of the desktop product.

use std::ffi::{c_char, c_void};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use serde::Serialize;

use super::TransferStore;
use crate::persistence::PersistenceError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PerformanceFixtureSpec {
    pub sessions: usize,
    pub jobs: usize,
    pub completions: usize,
    pub artifacts: usize,
    pub page_size: usize,
}

pub const SCORE_32_FIXTURE: PerformanceFixtureSpec = PerformanceFixtureSpec {
    sessions: 500,
    jobs: 10_000,
    completions: 10_000,
    artifacts: 50_000,
    page_size: 50,
};

pub const MINIMUM_P95_SPEEDUP: f64 = 5.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BenchmarkConfig {
    pub warmup_samples: usize,
    pub measured_samples: usize,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            warmup_samples: 2,
            measured_samples: 11,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TraceCounters {
    pub database_queries: usize,
    pub metadata_calls: usize,
    pub returned_job_states: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionTraceKind {
    FirstEntry,
    ManualRefresh,
    BackgroundRefresh,
    OpenDetail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SessionTraceObservation {
    pub kind: SessionTraceKind,
    pub requested_sessions: usize,
    pub remote_requests: usize,
    pub database_queries: usize,
    pub metadata_calls: usize,
    pub returned_job_states: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LatencyPercentiles {
    pub p50_ns: u64,
    pub p95_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceBenchmarkSummary {
    pub kind: SessionTraceKind,
    pub counters: SessionTraceObservation,
    pub latency: LatencyPercentiles,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueryScaleObservation {
    pub requested_sessions: usize,
    pub counters: TraceCounters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LegacyReferenceSummary {
    pub counters: TraceCounters,
    pub remote_requests: usize,
    pub latency: LatencyPercentiles,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PerformanceGateReport {
    pub minimum_p95_speedup: f64,
    pub observed_p95_speedup: f64,
    pub passed: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Score32BenchmarkReport {
    pub schema: &'static str,
    pub source_commit: Option<String>,
    pub runner_os: &'static str,
    pub runner_arch: &'static str,
    pub build_profile: &'static str,
    pub fixture: PerformanceFixtureSpec,
    pub config: BenchmarkConfig,
    pub query_scale: Vec<QueryScaleObservation>,
    pub traces: Vec<TraceBenchmarkSummary>,
    pub reference: LegacyReferenceSummary,
    pub gate: PerformanceGateReport,
}

#[derive(Debug, thiserror::Error)]
pub enum PerformanceBenchmarkError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),

    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    #[error("the benchmark database must be empty before seeding; found {0} job(s)")]
    DatabaseNotEmpty(u64),

    #[error("fixed Score #32 fixture mismatch: expected {expected:?}, observed {observed:?}")]
    FixtureMismatch {
        expected: PerformanceFixtureSpec,
        observed: PerformanceFixtureSpec,
    },

    #[error("benchmark measured_samples must be greater than zero")]
    EmptySampleSet,

    #[error("benchmark counters changed between samples for {trace:?}")]
    UnstableCounters { trace: SessionTraceKind },
}

pub struct Score32BenchmarkFixture {
    store: TransferStore,
    stored_counts: PerformanceFixtureSpec,
}

impl Score32BenchmarkFixture {
    pub fn create(path: impl Into<PathBuf>) -> Result<Self, PerformanceBenchmarkError> {
        let mut store = TransferStore::open(path.into())?;
        let existing_jobs = store.count_jobs()?;
        if existing_jobs != 0 {
            return Err(PerformanceBenchmarkError::DatabaseNotEmpty(existing_jobs));
        }
        seed_fixed_fixture(&mut store)?;
        let stored_counts = read_stored_counts(&store)?;
        if stored_counts != SCORE_32_FIXTURE {
            return Err(PerformanceBenchmarkError::FixtureMismatch {
                expected: SCORE_32_FIXTURE,
                observed: stored_counts,
            });
        }
        Ok(Self {
            store,
            stored_counts,
        })
    }

    #[must_use]
    pub fn stored_counts(&self) -> PerformanceFixtureSpec {
        self.stored_counts
    }

    pub fn measure_page_snapshot(
        &self,
        requested_sessions: usize,
    ) -> Result<TraceCounters, PerformanceBenchmarkError> {
        let device_ids = vec![fixture_device_id()];
        let session_ids = (0..requested_sessions)
            .map(fixture_session_id)
            .collect::<Vec<_>>();
        let (result, database_queries) = count_sql_statements(&self.store, |store| {
            store.list_download_session_job_states_for_sessions(&device_ids, &session_ids)
        });
        let returned_job_states = result?.len();
        Ok(TraceCounters {
            database_queries,
            metadata_calls: 0,
            returned_job_states,
        })
    }

    pub fn measure_trace(
        &self,
        kind: SessionTraceKind,
    ) -> Result<SessionTraceObservation, PerformanceBenchmarkError> {
        let mut adapters = CountingTraceAdapters::default();
        let requested_sessions = match kind {
            SessionTraceKind::FirstEntry
            | SessionTraceKind::ManualRefresh
            | SessionTraceKind::BackgroundRefresh => {
                adapters.request_catalog_page();
                SCORE_32_FIXTURE.page_size
            }
            SessionTraceKind::OpenDetail => {
                adapters.request_session_detail();
                adapters.probe_canonical_asset(&fixture_session_id(0));
                1
            }
        };
        let snapshot = self.measure_page_snapshot(requested_sessions)?;
        Ok(SessionTraceObservation {
            kind,
            requested_sessions,
            remote_requests: adapters.remote_requests,
            database_queries: snapshot.database_queries,
            metadata_calls: adapters.metadata_calls,
            returned_job_states: snapshot.returned_job_states,
        })
    }

    pub fn run(
        &self,
        config: BenchmarkConfig,
    ) -> Result<Score32BenchmarkReport, PerformanceBenchmarkError> {
        if config.measured_samples == 0 {
            return Err(PerformanceBenchmarkError::EmptySampleSet);
        }
        let trace_kinds = [
            SessionTraceKind::FirstEntry,
            SessionTraceKind::ManualRefresh,
            SessionTraceKind::BackgroundRefresh,
            SessionTraceKind::OpenDetail,
        ];
        for _ in 0..config.warmup_samples {
            for kind in trace_kinds {
                std::hint::black_box(self.measure_trace(kind)?);
            }
            std::hint::black_box(self.measure_legacy_reference()?);
        }

        let mut traces = Vec::with_capacity(trace_kinds.len());
        for kind in trace_kinds {
            traces.push(self.benchmark_trace(kind, config.measured_samples)?);
        }
        let reference = self.benchmark_legacy_reference(config.measured_samples)?;
        let query_scale = [0, 50, 500, 1_000]
            .into_iter()
            .map(|requested_sessions| {
                self.measure_page_snapshot(requested_sessions)
                    .map(|counters| QueryScaleObservation {
                        requested_sessions,
                        counters,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let gate = evaluate_gate(&traces, &reference, &query_scale);

        Ok(Score32BenchmarkReport {
            schema: "openaria.desktop.session-refresh-performance.v1",
            source_commit: None,
            runner_os: std::env::consts::OS,
            runner_arch: std::env::consts::ARCH,
            build_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            fixture: self.stored_counts,
            config,
            query_scale,
            traces,
            reference,
            gate,
        })
    }

    fn benchmark_trace(
        &self,
        kind: SessionTraceKind,
        measured_samples: usize,
    ) -> Result<TraceBenchmarkSummary, PerformanceBenchmarkError> {
        let mut counters = None;
        let mut durations = Vec::with_capacity(measured_samples);
        for _ in 0..measured_samples {
            let started = Instant::now();
            let observation = self.measure_trace(kind)?;
            durations.push(duration_ns(started.elapsed()));
            if counters.is_some_and(|expected| expected != observation) {
                return Err(PerformanceBenchmarkError::UnstableCounters { trace: kind });
            }
            counters = Some(observation);
        }
        Ok(TraceBenchmarkSummary {
            kind,
            counters: counters.expect("measured_samples was validated as non-zero"),
            latency: latency_percentiles(durations),
        })
    }

    fn benchmark_legacy_reference(
        &self,
        measured_samples: usize,
    ) -> Result<LegacyReferenceSummary, PerformanceBenchmarkError> {
        let mut counters = None;
        let mut durations = Vec::with_capacity(measured_samples);
        for _ in 0..measured_samples {
            let started = Instant::now();
            let observation = self.measure_legacy_reference()?;
            durations.push(duration_ns(started.elapsed()));
            if counters.is_some_and(|expected| expected != observation) {
                return Err(PerformanceBenchmarkError::UnstableCounters {
                    trace: SessionTraceKind::ManualRefresh,
                });
            }
            counters = Some(observation);
        }
        let counters = counters.expect("measured_samples was validated as non-zero");
        Ok(LegacyReferenceSummary {
            counters,
            remote_requests: 1,
            latency: latency_percentiles(durations),
        })
    }

    fn measure_legacy_reference(&self) -> Result<TraceCounters, PerformanceBenchmarkError> {
        let device_id = fixture_device_id();
        let page_session_ids = (0..SCORE_32_FIXTURE.page_size)
            .map(fixture_session_id)
            .collect::<Vec<_>>();
        let mut adapters = CountingTraceAdapters::default();
        adapters.request_catalog_page();
        let (result, database_queries) = count_sql_statements(&self.store, |store| {
            let mut returned_job_states = 0;
            for session_id in &page_session_ids {
                let jobs = store.list_jobs()?;
                for job in jobs.iter().filter(|job| {
                    job.identity.device_id().as_str() == device_id
                        && job.identity.session_id().as_str() == session_id
                }) {
                    std::hint::black_box(store.completion(&job.job_id)?);
                    returned_job_states += 1;
                }
                for ordinal in 0..SCORE_32_FIXTURE.artifacts {
                    adapters.probe_original_artifact(ordinal);
                }
            }
            Ok::<_, PerformanceBenchmarkError>(returned_job_states)
        });
        Ok(TraceCounters {
            database_queries,
            metadata_calls: adapters.metadata_calls,
            returned_job_states: result?,
        })
    }
}

#[derive(Default)]
struct CountingTraceAdapters {
    remote_requests: usize,
    metadata_calls: usize,
}

impl CountingTraceAdapters {
    fn request_catalog_page(&mut self) {
        self.remote_requests += 1;
    }

    fn request_session_detail(&mut self) {
        self.remote_requests += 1;
    }

    fn probe_canonical_asset(&mut self, session_id: &str) {
        let canonical_path = format!("processed/{session_id}.mp4");
        debug_assert!(canonical_path.starts_with("processed/"));
        self.metadata_calls += 1;
    }

    fn probe_original_artifact(&mut self, ordinal: usize) {
        std::hint::black_box(ordinal);
        self.metadata_calls += 1;
    }
}

fn duration_ns(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn latency_percentiles(mut samples: Vec<u64>) -> LatencyPercentiles {
    samples.sort_unstable();
    LatencyPercentiles {
        p50_ns: nearest_rank(&samples, 50),
        p95_ns: nearest_rank(&samples, 95),
    }
}

fn nearest_rank(samples: &[u64], percentile: usize) -> u64 {
    let rank = samples.len().saturating_mul(percentile).div_ceil(100);
    samples[rank.saturating_sub(1).min(samples.len() - 1)]
}

fn evaluate_gate(
    traces: &[TraceBenchmarkSummary],
    reference: &LegacyReferenceSummary,
    query_scale: &[QueryScaleObservation],
) -> PerformanceGateReport {
    let mut failures = Vec::new();
    for trace in traces {
        let expected_sessions = if trace.kind == SessionTraceKind::OpenDetail {
            1
        } else {
            SCORE_32_FIXTURE.page_size
        };
        let expected_metadata = usize::from(trace.kind == SessionTraceKind::OpenDetail);
        let expected_job_states = expected_sessions
            .min(SCORE_32_FIXTURE.sessions)
            .saturating_mul(SCORE_32_FIXTURE.jobs / SCORE_32_FIXTURE.sessions);
        if trace.counters.requested_sessions != expected_sessions
            || trace.counters.remote_requests != 1
            || trace.counters.database_queries != 1
            || trace.counters.metadata_calls != expected_metadata
            || trace.counters.returned_job_states != expected_job_states
        {
            failures.push(format!(
                "{:?} exceeded its request/query/metadata budget: {:?}",
                trace.kind, trace.counters
            ));
        }
    }
    for observation in query_scale {
        let expected_job_states = observation
            .requested_sessions
            .min(SCORE_32_FIXTURE.sessions)
            .saturating_mul(SCORE_32_FIXTURE.jobs / SCORE_32_FIXTURE.sessions);
        if observation.counters.database_queries != 1
            || observation.counters.metadata_calls != 0
            || observation.counters.returned_job_states != expected_job_states
        {
            failures.push(format!(
                "{} requested sessions produced unexpected counters: {:?}",
                observation.requested_sessions, observation.counters
            ));
        }
    }
    let expected_reference_queries =
        SCORE_32_FIXTURE.page_size * (1 + SCORE_32_FIXTURE.jobs / SCORE_32_FIXTURE.sessions);
    let expected_reference_metadata = SCORE_32_FIXTURE.page_size * SCORE_32_FIXTURE.artifacts;
    if reference.counters.database_queries != expected_reference_queries
        || reference.counters.metadata_calls != expected_reference_metadata
        || reference.counters.returned_job_states
            != SCORE_32_FIXTURE.page_size * (SCORE_32_FIXTURE.jobs / SCORE_32_FIXTURE.sessions)
        || reference.remote_requests != 1
    {
        failures.push(format!(
            "legacy reference identity changed: {:?}",
            reference.counters
        ));
    }
    let manual_refresh_p95 = traces
        .iter()
        .find(|trace| trace.kind == SessionTraceKind::ManualRefresh)
        .map(|trace| trace.latency.p95_ns)
        .unwrap_or(u64::MAX);
    let observed_p95_speedup = if manual_refresh_p95 == 0 {
        f64::MAX
    } else {
        reference.latency.p95_ns as f64 / manual_refresh_p95 as f64
    };
    if !observed_p95_speedup.is_finite() || observed_p95_speedup < MINIMUM_P95_SPEEDUP {
        failures.push(format!(
            "manual refresh p95 speedup {observed_p95_speedup:.2}x is below {MINIMUM_P95_SPEEDUP:.2}x"
        ));
    }
    PerformanceGateReport {
        minimum_p95_speedup: MINIMUM_P95_SPEEDUP,
        observed_p95_speedup,
        passed: failures.is_empty(),
        failures,
    }
}

fn fixture_device_id() -> String {
    "pi-score-32".to_string()
}

fn fixture_session_id(index: usize) -> String {
    format!("session-{index:04}")
}

fn seed_fixed_fixture(store: &mut TransferStore) -> Result<(), PerformanceBenchmarkError> {
    let transaction = store.conn.transaction()?;
    {
        let mut insert_job = transaction.prepare(
            "INSERT INTO transfer_jobs (
                job_id, natural_key, device_id, session_id, revision,
                request_digest, state, state_version, error_code,
                error_retryable, created_at, updated_at, desired_run_state,
                operation_kind
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, 'succeeded', 2, NULL, NULL,
                ?7, ?7, 'run', 'download'
             )",
        )?;
        let mut insert_completion = transaction.prepare(
            "INSERT INTO transfer_completion_outbox (
                job_id, outcome, error_code, error_retryable,
                state_version, recorded_at, acknowledged_at, operation_kind
             ) VALUES (?1, 'succeeded', NULL, NULL, 2, ?2, ?2, 'download')",
        )?;
        let mut insert_artifact = transaction.prepare(
            "INSERT INTO transfer_job_files (
                job_id, inventory_index, request_index, file_id,
                display_path, size_bytes, sha256
             ) VALUES (?1, ?2, ?2, ?3, ?4, 1, ?5)",
        )?;
        let device_id = fixture_device_id();
        let request_digest = "0".repeat(64);
        let artifacts_per_job = SCORE_32_FIXTURE.artifacts / SCORE_32_FIXTURE.jobs;

        for job_index in 0..SCORE_32_FIXTURE.jobs {
            let session_index = job_index % SCORE_32_FIXTURE.sessions;
            let job_id = format!("job-{job_index:05}");
            let natural_key = format!("score-32-natural-{job_index:05}");
            let session_id = fixture_session_id(session_index);
            let revision = format!("revision-{job_index:05}");
            let timestamp = format!("2026-08-29T00:{:02}:{:02}Z", job_index % 60, job_index % 60);
            insert_job.execute(rusqlite::params![
                job_id,
                natural_key,
                device_id,
                session_id,
                revision,
                request_digest,
                timestamp,
            ])?;
            insert_completion.execute(rusqlite::params![job_id, timestamp])?;

            for artifact_index in 0..artifacts_per_job {
                let ordinal = job_index * artifacts_per_job + artifact_index;
                let file_id = format!("artifact-{ordinal:05}");
                let display_path = format!("raw/{file_id}.bin");
                let sha256 = format!("{ordinal:064x}");
                insert_artifact.execute(rusqlite::params![
                    job_id,
                    i64::try_from(artifact_index).expect("artifact index fits i64"),
                    file_id,
                    display_path,
                    sha256,
                ])?;
            }
        }
    }
    transaction.commit()?;
    Ok(())
}

fn read_stored_counts(
    store: &TransferStore,
) -> Result<PerformanceFixtureSpec, PerformanceBenchmarkError> {
    let count = |table: &str| -> Result<usize, PerformanceBenchmarkError> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let value = store.conn.query_row(&sql, [], |row| row.get::<_, i64>(0))?;
        usize::try_from(value).map_err(|_| {
            PerformanceBenchmarkError::Persistence(PersistenceError::Corrupt {
                path: PathBuf::from(table),
                detail: format!("negative row count {value}"),
            })
        })
    };
    let sessions = store.conn.query_row(
        "SELECT COUNT(DISTINCT session_id) FROM transfer_jobs",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let sessions = usize::try_from(sessions).map_err(|_| {
        PerformanceBenchmarkError::Persistence(PersistenceError::Corrupt {
            path: PathBuf::from("transfer_jobs"),
            detail: format!("negative distinct session count {sessions}"),
        })
    })?;
    Ok(PerformanceFixtureSpec {
        sessions,
        jobs: count("transfer_jobs")?,
        completions: count("transfer_completion_outbox")?,
        artifacts: count("transfer_job_files")?,
        page_size: SCORE_32_FIXTURE.page_size,
    })
}

unsafe extern "C" fn increment_statement_count(context: *mut c_void, _sql: *const c_char) {
    // SQLite invokes this synchronously while the trace guard and counter are
    // alive. The guard clears the callback before the counter can be dropped.
    let counter = unsafe { &*context.cast::<AtomicUsize>() };
    counter.fetch_add(1, Ordering::Relaxed);
}

struct SqlTraceGuard(*mut rusqlite::ffi::sqlite3);

impl Drop for SqlTraceGuard {
    fn drop(&mut self) {
        unsafe {
            rusqlite::ffi::sqlite3_trace(self.0, None, ptr::null_mut());
        }
    }
}

fn count_sql_statements<T>(
    store: &TransferStore,
    operation: impl FnOnce(&TransferStore) -> T,
) -> (T, usize) {
    let counter = AtomicUsize::new(0);
    let handle = unsafe { store.conn.handle() };
    unsafe {
        rusqlite::ffi::sqlite3_trace(
            handle,
            Some(increment_statement_count),
            (&counter as *const AtomicUsize).cast_mut().cast(),
        );
    }
    let guard = SqlTraceGuard(handle);
    let result = operation(store);
    drop(guard);
    (result, counter.load(Ordering::Relaxed))
}
