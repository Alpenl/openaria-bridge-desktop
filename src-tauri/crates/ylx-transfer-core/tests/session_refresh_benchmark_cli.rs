#![cfg(feature = "performance-benchmark")]

use std::process::Command;

#[test]
fn cli_writes_a_machine_readable_passing_report() {
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let output = directory.path().join("report.json");
    let result = Command::new(env!("CARGO_BIN_EXE_session-refresh-benchmark"))
        .args([
            "--warmup",
            "0",
            "--samples",
            "1",
            "--source-commit",
            "0123456789abcdef0123456789abcdef01234567",
            "--output",
            output.to_str().expect("UTF-8 temp path"),
        ])
        .output()
        .expect("run benchmark CLI");

    assert!(
        result.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output).expect("read report")).expect("JSON report");
    assert_eq!(
        report["schema"],
        "openaria.desktop.session-refresh-performance.v1"
    );
    assert_eq!(report["fixture"]["sessions"], 500);
    assert_eq!(report["fixture"]["jobs"], 10_000);
    assert_eq!(report["fixture"]["completions"], 10_000);
    assert_eq!(report["fixture"]["artifacts"], 50_000);
    assert_eq!(
        report["source_commit"],
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert_eq!(report["gate"]["passed"], true);
}

#[test]
fn cli_rejects_an_empty_sample_set_before_creating_a_report() {
    let directory = tempfile::tempdir().expect("benchmark tempdir");
    let output = directory.path().join("report.json");
    let result = Command::new(env!("CARGO_BIN_EXE_session-refresh-benchmark"))
        .args([
            "--samples",
            "0",
            "--output",
            output.to_str().expect("UTF-8 temp path"),
        ])
        .output()
        .expect("run benchmark CLI");

    assert_eq!(result.status.code(), Some(2));
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--samples must be greater than zero"));
}
