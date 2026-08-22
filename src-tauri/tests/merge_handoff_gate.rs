use serde_json::Value;

const WORKSPACE_TOML: &str = include_str!("../Cargo.toml");
const PACKAGE_JSON: &str = include_str!("../../package.json");
const DEVICE_SESSION_GATE: &str =
    include_str!("../crates/ylx-transfer-core/tests/device_session_v1_admission.rs");
const MOUNTED_FILE_GATE: &str = include_str!("../crates/ylx-transfer-adapters/src/mounted_file.rs");

#[test]
fn workspace_includes_transfer_gate_packages() {
    assert!(
        WORKSPACE_TOML.contains("\"crates/ylx-transfer-core\""),
        "workspace must include ylx-transfer-core so Device Session contract tests run"
    );
    assert!(
        WORKSPACE_TOML.contains("\"crates/ylx-transfer-adapters\""),
        "workspace must include ylx-transfer-adapters so mounted-file hostile tests run"
    );
}

#[test]
fn rust_gate_sources_include_device_session_contract_and_hostile_filesystem_tests() {
    for required_test in [
        "pins_the_central_device_session_v1_contract_identity",
        "vendored_contract_tree_is_reference_only_and_hash_checked",
        "central_valid_device_session_corpus_scans_as_pending_without_artifact_files",
        "central_invalid_device_session_local_corpus_fails_closed",
        "manifest_symlink_and_hardlink_fail_closed_before_parsing",
    ] {
        assert!(
            DEVICE_SESSION_GATE.contains(required_test),
            "Device Session gate must retain {required_test}"
        );
    }

    for required_test in [
        "symlink_artifact_is_rejected_without_following_it",
        "symlink_parent_directory_is_rejected_without_following_it",
        "hardlinked_artifact_is_rejected_before_reading",
        "hardlink_added_after_open_is_a_typed_precondition_failure",
        "same_size_wrong_content_fails_the_frozen_hash_claim",
    ] {
        assert!(
            MOUNTED_FILE_GATE.contains(required_test),
            "mounted-file hostile gate must retain {required_test}"
        );
    }
}

#[test]
fn package_scripts_keep_frontend_gate_commands() {
    let package: Value = serde_json::from_str(PACKAGE_JSON).expect("package.json");
    assert_eq!(
        package.pointer("/scripts/test").and_then(Value::as_str),
        Some("node ./src/test-support/run-tests.mjs")
    );
    assert_eq!(
        package
            .pointer("/scripts/typecheck")
            .and_then(Value::as_str),
        Some("tsc --noEmit")
    );
    assert_eq!(
        package.pointer("/scripts/lint").and_then(Value::as_str),
        Some("eslint .")
    );
    assert_eq!(
        package
            .pointer("/scripts/format:check")
            .and_then(Value::as_str),
        Some("prettier --check .")
    );
}
