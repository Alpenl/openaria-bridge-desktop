#![cfg(feature = "performance-benchmark")]

use ylx_transfer_core::persistence::transfer_store::performance::{
    BenchmarkConfig, Score32BenchmarkFixture, SessionTraceKind, SCORE_32_FIXTURE,
};

#[test]
fn score_32_fixture_identity_is_fixed() {
    assert_eq!(SCORE_32_FIXTURE.sessions, 500);
    assert_eq!(SCORE_32_FIXTURE.jobs, 10_000);
    assert_eq!(SCORE_32_FIXTURE.completions, 10_000);
    assert_eq!(SCORE_32_FIXTURE.artifacts, 50_000);
    assert_eq!(SCORE_32_FIXTURE.page_size, 50);
}

#[test]
fn page_snapshot_query_and_metadata_counts_are_constant_at_scale() {
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let fixture = Score32BenchmarkFixture::create(directory.path().join("score-32.sqlite3"))
        .expect("create fixed benchmark fixture");

    assert_eq!(fixture.stored_counts(), SCORE_32_FIXTURE);
    for requested_sessions in [0, 50, 500, 1_000] {
        let observation = fixture
            .measure_page_snapshot(requested_sessions)
            .expect("measure page snapshot");
        assert_eq!(
            observation.database_queries, 1,
            "requested session count {requested_sessions} changed the SQL statement count"
        );
        assert_eq!(observation.metadata_calls, 0);
    }
}

#[test]
fn user_traces_keep_remote_database_and_metadata_work_bounded() {
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let fixture = Score32BenchmarkFixture::create(directory.path().join("score-32.sqlite3"))
        .expect("create fixed benchmark fixture");

    for kind in [
        SessionTraceKind::FirstEntry,
        SessionTraceKind::ManualRefresh,
        SessionTraceKind::BackgroundRefresh,
    ] {
        let observation = fixture.measure_trace(kind).expect("measure page trace");
        assert_eq!(observation.requested_sessions, SCORE_32_FIXTURE.page_size);
        assert_eq!(observation.remote_requests, 1);
        assert_eq!(observation.database_queries, 1);
        assert_eq!(observation.metadata_calls, 0);
        assert_eq!(observation.returned_job_states, 1_000);
    }

    let detail = fixture
        .measure_trace(SessionTraceKind::OpenDetail)
        .expect("measure detail trace");
    assert_eq!(detail.requested_sessions, 1);
    assert_eq!(detail.remote_requests, 1);
    assert_eq!(detail.database_queries, 1);
    assert_eq!(detail.metadata_calls, 1);
    assert_eq!(detail.returned_job_states, 20);
}

#[test]
fn reference_benchmark_enforces_a_five_times_p95_improvement() {
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let fixture = Score32BenchmarkFixture::create(directory.path().join("score-32.sqlite3"))
        .expect("create fixed benchmark fixture");
    let report = fixture
        .run(BenchmarkConfig {
            warmup_samples: 1,
            measured_samples: 5,
        })
        .expect("run reference benchmark");

    assert!(
        report.gate.passed,
        "gate failures: {:?}",
        report.gate.failures
    );
    assert!(report.gate.observed_p95_speedup >= 5.0);
    assert_eq!(report.reference.counters.database_queries, 1_050);
    assert_eq!(report.reference.counters.metadata_calls, 2_500_000);
    for trace in &report.traces {
        assert!(trace.latency.p50_ns <= trace.latency.p95_ns);
    }
}
