use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use ylx_transfer_adapters::publication_verifier::Ed25519PublicationVerifier;
use ylx_transfer_core::ingest::{
    AcquisitionSourceId, CandidateReadiness, ConstrainedScanner, InventoryDigest, MediaGeneration,
    SafeRelativePath, ScanCandidate, ScanItemOutcome, ScanLimits, ScanRequest, SourceKind,
    SourceRecording, SourceSchema,
};
use ylx_transfer_core::publication::{parse_strict_json, PublicationTrust};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/removable-media")
}

fn read_json(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    parse_strict_json(&bytes)
        .unwrap_or_else(|error| panic!("strict JSON {}: {error}", path.display()))
}

fn required_str<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string {pointer}"))
}

fn required_array<'a>(value: &'a Value, pointer: &str) -> &'a [Value] {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("missing array {pointer}"))
}

fn payload_bytes(payload: &Value) -> Vec<u8> {
    match required_str(payload, "/encoding") {
        "utf8" => required_str(payload, "/data").as_bytes().to_vec(),
        "hex" => decode_hex(required_str(payload, "/data")),
        other => panic!("unsupported fixture payload encoding {other:?}"),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex payload has odd length");
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let high = char::from(bytes[index]).to_digit(16).expect("hex digit") as u8;
        let low = char::from(bytes[index + 1])
            .to_digit(16)
            .expect("hex digit") as u8;
        decoded.push((high << 4) | low);
    }
    decoded
}

fn canonical_json(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut String) {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => output
                .push_str(&serde_json::to_string(value).expect("a JSON string always serializes")),
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(value, output);
                }
                output.push(']');
            }
            Value::Object(values) => {
                output.push('{');
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(
                        &serde_json::to_string(key).expect("a JSON object key always serializes"),
                    );
                    output.push(':');
                    write(&values[key], output);
                }
                output.push('}');
            }
        }
    }

    let mut output = String::new();
    write(value, &mut output);
    output.into_bytes()
}

fn safe_path(root: &Path, value: &str) -> PathBuf {
    SafeRelativePath::parse(value.to_string())
        .unwrap_or_else(|error| panic!("unsafe fixture path {value:?}: {error}"))
        .join_to(root)
}

fn remove_entry(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).expect("remove fixture directory");
        }
        Ok(_) => fs::remove_file(path).expect("remove fixture entry"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("inspect fixture entry {}: {error}", path.display()),
    }
}

fn write_entry(root: &Path, entry: &Value, payloads: &serde_json::Map<String, Value>) {
    let relative = required_str(entry, "/path");
    let path = safe_path(root, relative);
    if path.exists() || fs::symlink_metadata(&path).is_ok() {
        remove_entry(&path);
    }
    fs::create_dir_all(path.parent().expect("fixture entry has a parent"))
        .expect("create fixture parent");

    match required_str(entry, "/kind") {
        "json" => fs::write(&path, canonical_json(&entry["document"]))
            .expect("write canonical fixture JSON"),
        "utf8" => fs::write(&path, required_str(entry, "/content_utf8").as_bytes())
            .expect("write fixture text"),
        "payload" => {
            let id = required_str(entry, "/payload_id");
            let payload = payloads
                .get(id)
                .unwrap_or_else(|| panic!("unknown payload id {id:?}"));
            fs::write(&path, payload_bytes(payload)).expect("write fixture payload");
        }
        // The fixture contract permits non-regular entries to be simulated.
        // A directory is portable across the CI OS matrix and exercises the
        // same no-open boundary without requiring symlink privileges.
        "symlink" | "reparse_point" => {
            fs::create_dir(&path).expect("create simulated non-regular entry");
        }
        other => panic!("unsupported fixture entry kind {other:?}"),
    }
}

fn apply_mutation(root: &Path, mutation: &Value, payloads: &serde_json::Map<String, Value>) {
    let operation = required_str(mutation, "/operation");
    match operation {
        "remove_entry" => remove_entry(&safe_path(root, required_str(mutation, "/path"))),
        "add_entry" => write_entry(root, &mutation["entry"], payloads),
        "replace_json" => write_entry(
            root,
            &serde_json::json!({
                "path": required_str(mutation, "/path"),
                "kind": "json",
                "document": mutation["document"].clone(),
            }),
            payloads,
        ),
        "replace_utf8" => write_entry(
            root,
            &serde_json::json!({
                "path": required_str(mutation, "/path"),
                "kind": "utf8",
                "content_utf8": required_str(mutation, "/content_utf8"),
            }),
            payloads,
        ),
        "replace_payload" => write_entry(
            root,
            &serde_json::json!({
                "path": required_str(mutation, "/path"),
                "kind": "payload",
                "payload_id": required_str(mutation, "/payload_id"),
            }),
            payloads,
        ),
        "replace_entry_kind" => write_entry(root, mutation, payloads),
        other => panic!("unsupported fixture mutation {other:?}"),
    }
}

fn materialize_case(
    root: &Path,
    group: &Value,
    case: &Value,
    payloads: &serde_json::Map<String, Value>,
) {
    let tree = case
        .get("tree")
        .and_then(Value::as_array)
        .or_else(|| group.get("base_tree").and_then(Value::as_array))
        .unwrap_or_else(|| panic!("fixture case has neither tree nor base_tree"));
    for entry in tree {
        write_entry(root, entry, payloads);
    }
    for mutation in case
        .get("mutations")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        apply_mutation(root, mutation, payloads);
    }
}

fn candidate_root(root: &Path) -> PathBuf {
    let markers = ["publication_manifest.json", "session.json", "capture.json"];
    let mut stack = vec![root.to_path_buf()];
    let mut parents = BTreeSet::new();
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).expect("read materialized fixture directory") {
            let entry = entry.expect("fixture directory entry");
            let metadata = entry.metadata().expect("fixture entry metadata");
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if markers.contains(&entry.file_name().to_string_lossy().as_ref()) {
                parents.insert(directory.clone());
            }
        }
    }
    assert_eq!(
        parents.len(),
        1,
        "one fixture case must materialize exactly one candidate root: {parents:?}"
    );
    parents.pop_first().expect("one candidate root")
}

fn scan(root: &Path) -> ScanItemOutcome {
    let source_id = AcquisitionSourceId::parse("fixture-volume").expect("source id");
    let generation = MediaGeneration::new(
        source_id.clone(),
        "fixture-platform-volume",
        InventoryDigest::from_material(b"fixture-root-marker"),
        1,
    )
    .expect("media generation");
    let request = ScanRequest::selected_directory(
        root,
        source_id,
        SourceKind::RemovableMedia,
        Some(generation),
    )
    .expect("fixture scan request");
    ConstrainedScanner::new(ScanLimits::default())
        .scan(&request)
        .items()
        .first()
        .expect("selected directory produces one outcome")
        .outcome()
        .clone()
}

fn readiness_name(readiness: CandidateReadiness) -> &'static str {
    match readiness {
        CandidateReadiness::ReadySigned => "ready_signed",
        CandidateReadiness::ReadyUnsignedRequiresPolicy => "ready_unsigned_requires_policy",
        CandidateReadiness::PendingArtifactValidation => "pending_artifact_validation",
        CandidateReadiness::AlreadyImported => "already_imported",
        CandidateReadiness::WaitingForPairingKey => "waiting_for_pairing_key",
        CandidateReadiness::InsufficientLocalSpace => "insufficient_local_space",
        CandidateReadiness::RecordingOrEncodingIncomplete => "recording_or_encoding_incomplete",
        CandidateReadiness::UnsupportedSchema => "unsupported_schema",
        CandidateReadiness::UnsafePath => "unsafe_path",
        CandidateReadiness::Corrupt => "corrupt",
    }
}

fn schema_classification(schema: SourceSchema) -> &'static str {
    match schema {
        SourceSchema::DeviceSessionV1 => "DeviceSessionV1",
        SourceSchema::DeviceSessionV2 => "DeviceSessionV2",
        SourceSchema::SignedPublicationV1 => "TrustedPublished",
        SourceSchema::UnsignedPublicationV1 => "UnsignedPublicationV1",
        SourceSchema::RawCaptureV2 => "SdkRawCapture",
        SourceSchema::LegacyMjpegSessionV5 => "LegacyMjpegSessionV5",
        SourceSchema::CompleteUnpublishedV6 => "CompleteUnpublished",
        SourceSchema::ApplianceSpoolV6 => "CommittedRawSpool",
    }
}

fn inventory_matches(root: &Path, candidate: &ScanCandidate) -> bool {
    candidate.inventory().iter().all(|claim| {
        let Some(expected) = claim.source_sha256() else {
            return true;
        };
        fs::read(claim.relative_path().join_to(root))
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)) == expected)
            .unwrap_or(false)
    })
}

fn assert_case_verdict(
    id: &str,
    expected: &Value,
    root: &Path,
    outcome: ScanItemOutcome,
    trust_anchor: &Value,
) {
    let expected_verdict = required_str(expected, "/preflight_verdict");
    let expected_classification = required_str(expected, "/classification");
    match outcome {
        ScanItemOutcome::Rejected { readiness, .. } => {
            assert_eq!(
                readiness_name(readiness),
                expected_verdict,
                "fixture {id} rejection verdict"
            );
            assert!(
                matches!(
                    expected_classification,
                    "Rejected" | "RecoveryOnly" | "UnsupportedLegacy"
                ),
                "fixture {id} unexpectedly rejected classification {expected_classification}"
            );
        }
        ScanItemOutcome::Candidate { candidate } => {
            if !inventory_matches(root, &candidate) {
                assert_eq!(
                    expected_verdict, "corrupt",
                    "fixture {id} has a content mismatch but expected another verdict"
                );
                assert_eq!(expected_classification, "RecoveryOnly");
                return;
            }

            if expected_verdict == "waiting_for_pairing_key" {
                assert_eq!(candidate.schema(), SourceSchema::SignedPublicationV1);
                assert_eq!(expected_classification, "Rejected");
            } else {
                assert_eq!(
                    schema_classification(candidate.schema()),
                    expected_classification,
                    "fixture {id} classification"
                );
            }
            if expected_verdict == "ready_signed" {
                assert_eq!(
                    candidate.readiness(),
                    CandidateReadiness::WaitingForPairingKey
                );
                let material = candidate
                    .signed_publication()
                    .expect("ready_signed fixture carries exact material");
                let anchor = required_str(trust_anchor, "/fingerprint");
                assert_eq!(material.presented_key_fingerprint(), anchor);
                let verified = PublicationTrust::new(&Ed25519PublicationVerifier)
                    .verify(&material.envelope(), candidate.session_id(), anchor)
                    .unwrap_or_else(|error| panic!("fixture {id} signature: {error}"));
                SourceRecording::admit_device_signed(*candidate, &verified)
                    .unwrap_or_else(|error| panic!("fixture {id} signed admission: {error}"));
            } else {
                assert_eq!(
                    readiness_name(candidate.readiness()),
                    expected_verdict,
                    "fixture {id} candidate verdict"
                );
                if expected_verdict == "waiting_for_pairing_key" {
                    let material = candidate
                        .signed_publication()
                        .expect("unpaired fixture still carries exact signed material");
                    PublicationTrust::new(&Ed25519PublicationVerifier)
                        .verify(
                            &material.envelope(),
                            candidate.session_id(),
                            required_str(trust_anchor, "/fingerprint"),
                        )
                        .unwrap_or_else(|error| {
                            panic!("fixture {id} must be cryptographically valid: {error}")
                        });
                }
            }
        }
    }
}

#[test]
fn fixture_metadata_is_closed_strict_and_digest_checked() {
    let root = fixture_root();
    let contract = read_json(&root.join("fixture-contract-v1.json"));
    let index = read_json(&root.join("index.json"));
    let provenance = read_json(&root.join("provenance.json"));
    let payload_catalog = read_json(&root.join("payloads.json"));

    assert_eq!(
        required_str(&contract, "/fixture_schema"),
        "ylx.removable_media.fixture_contract.v1"
    );
    let payloads = payload_catalog["payloads"]
        .as_object()
        .expect("payload object");
    for (id, payload) in payloads {
        let bytes = payload_bytes(payload);
        assert_eq!(
            bytes.len() as u64,
            payload["size_bytes"].as_u64().expect("payload size"),
            "payload {id} size"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            required_str(payload, "/sha256"),
            "payload {id} digest"
        );
    }

    let mut group_cases = BTreeMap::new();
    let classifications = required_array(&contract, "/classifications")
        .iter()
        .map(|value| value.as_str().expect("classification string"))
        .collect::<BTreeSet<_>>();
    let verdicts = required_array(&contract, "/preflight_verdicts")
        .iter()
        .map(|value| value.as_str().expect("verdict string"))
        .collect::<BTreeSet<_>>();
    let provenance_values = required_array(&contract, "/provenance_values")
        .iter()
        .map(|value| value.as_str().expect("provenance string"))
        .collect::<BTreeSet<_>>();
    for case_file in required_array(&contract, "/case_files") {
        let case_file = case_file.as_str().expect("case file string");
        SafeRelativePath::parse(case_file.to_string()).expect("safe case file path");
        let group = read_json(&root.join(case_file));
        assert_eq!(
            required_str(&group, "/fixture_schema"),
            "ylx.removable_media.case_group.v1"
        );
        for case in required_array(&group, "/cases") {
            let id = required_str(case, "/id").to_string();
            assert!(
                classifications.contains(required_str(case, "/expected/classification")),
                "case {id} uses an undeclared classification"
            );
            assert!(
                verdicts.contains(required_str(case, "/expected/preflight_verdict")),
                "case {id} uses an undeclared preflight verdict"
            );
            assert!(
                provenance_values.contains(required_str(case, "/expected/provenance")),
                "case {id} uses an undeclared provenance value"
            );
            assert!(
                group_cases
                    .insert(id.clone(), (case_file.to_string(), case.clone()))
                    .is_none(),
                "duplicate case id {id}"
            );
        }
    }

    let indexed = required_array(&index, "/fixtures");
    assert_eq!(index["fixture_count"].as_u64(), Some(indexed.len() as u64));
    assert_eq!(indexed.len(), group_cases.len());
    let provenance_entries = required_array(&provenance, "/fixtures");
    assert_eq!(provenance_entries.len(), indexed.len());

    let provenance_by_id = provenance_entries
        .iter()
        .map(|entry| (required_str(entry, "/id"), entry))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(provenance_by_id.len(), provenance_entries.len());
    for entry in indexed {
        let id = required_str(entry, "/id");
        let (case_file, case) = group_cases
            .get(id)
            .unwrap_or_else(|| panic!("indexed case {id} is missing"));
        assert_eq!(required_str(entry, "/case_file"), case_file);
        assert_eq!(
            required_str(entry, "/expected"),
            required_str(case, "/expected/preflight_verdict")
        );
        let source = provenance_by_id
            .get(id)
            .unwrap_or_else(|| panic!("case {id} has no provenance"));
        assert_eq!(required_str(source, "/case_file"), case_file);
        assert_eq!(required_str(source, "/case_id"), id);
        assert_eq!(
            required_str(source, "/expected_verdict"),
            required_str(entry, "/expected")
        );
    }
    assert_eq!(
        provenance["provenance_policy"]["raw_material_retained"].as_bool(),
        Some(false)
    );
    assert!(provenance["provenance_policy"]["raw_digest"].is_null());
    let trust = read_json(&root.join("trust/test-only-ed25519.json"));
    assert_eq!(trust["private_key_committed"].as_bool(), Some(false));
    assert_eq!(required_str(&trust, "/scope"), "TEST_ONLY");
}

#[test]
fn every_materialized_fixture_matches_its_preflight_contract() {
    let root = fixture_root();
    let contract = read_json(&root.join("fixture-contract-v1.json"));
    let index = read_json(&root.join("index.json"));
    let payload_catalog = read_json(&root.join("payloads.json"));
    let payloads = payload_catalog["payloads"]
        .as_object()
        .expect("payload object");
    let trust_anchor = read_json(&root.join("trust/test-only-ed25519.json"));

    let groups = required_array(&contract, "/case_files")
        .iter()
        .map(|path| {
            let path = path.as_str().expect("case file string");
            (path.to_string(), read_json(&root.join(path)))
        })
        .collect::<BTreeMap<_, _>>();
    for entry in required_array(&index, "/fixtures") {
        let id = required_str(entry, "/id");
        let case_file = required_str(entry, "/case_file");
        let group = groups
            .get(case_file)
            .unwrap_or_else(|| panic!("unknown case file {case_file}"));
        let case = required_array(group, "/cases")
            .iter()
            .find(|case| required_str(case, "/id") == id)
            .unwrap_or_else(|| panic!("missing case {id}"));
        let temporary = tempfile::tempdir().expect("fixture tempdir");
        materialize_case(temporary.path(), group, case, payloads);
        let candidate = candidate_root(temporary.path());
        assert_case_verdict(
            id,
            &case["expected"],
            &candidate,
            scan(&candidate),
            &trust_anchor,
        );
    }
}
