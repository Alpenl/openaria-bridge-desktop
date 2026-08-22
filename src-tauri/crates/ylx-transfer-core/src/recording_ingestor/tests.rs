use super::engine::bounded_text;
use super::reader_gate::{lock, PhysicalMediaKey, ReaderGateRegistry};

use crate::ingest::SafeRelativePath;
use crate::ingest::{
    AcquisitionSourceId, AdmissionError, CandidateId, CandidateReadiness, CandidateRevision,
    ImportCommand, ImportEffect, ImportJob, ImportPolicy, MediaGeneration, MediaLocator,
    ScanCandidate, SourceArtifactClaim, SourceArtifactId, SourceArtifactRole, SourceKind,
    SourceMediaPlan, SourceRecording, SourceRevisionClaim, SourceSchema, SourceTrustVerdicts,
    SourceVideoCodec, StereoLayout, UnsignedImportPolicy, UnsignedSourceAdmissionReceipt,
    ValidationCheck, ValidationReport,
};

#[test]
fn bounded_text_removes_controls_and_caps_diagnostics() {
    let input = format!("before\n{}after", "x".repeat(2_000));
    let output = bounded_text(input);
    assert!(output.len() <= 1_024);
    assert!(!output.chars().any(char::is_control));
}

#[test]
fn physical_media_gate_ignores_observation_epoch() {
    let source_id = AcquisitionSourceId::parse("card-reader").expect("source id");
    let marker = crate::ingest::InventoryDigest::from_material(b"root");
    let first =
        MediaGeneration::new(source_id.clone(), "volume-a", marker.clone(), 1).expect("generation");
    let second =
        MediaGeneration::new(source_id.clone(), "volume-a", marker, 2).expect("generation");
    let first_locator = MediaLocator::new(source_id.clone(), Some(first), None);
    let second_locator = MediaLocator::new(source_id, Some(second), None);
    assert_eq!(
        PhysicalMediaKey::from_locator(&first_locator),
        PhysicalMediaKey::from_locator(&second_locator)
    );

    let gates = ReaderGateRegistry::default();
    let key = PhysicalMediaKey::from_locator(&first_locator).expect("physical key");
    let gate = gates.gate_for(&key);
    let _guard = lock(&gate);
}

#[test]
fn reducer_persists_before_preflight_effect() {
    let source_id = AcquisitionSourceId::parse("folder").expect("source id");
    let locator = MediaLocator::new(source_id, None, None);
    let claim = SourceArtifactClaim::new(
        SourceArtifactId::parse("metadata").expect("artifact id"),
        SafeRelativePath::parse("capture.json").expect("path"),
        SourceArtifactRole::Metadata,
        1,
        None,
        Some("application/json".to_string()),
    )
    .expect("claim");
    let plan = SourceMediaPlan::new(
        StereoLayout::SeparateEyes,
        SourceVideoCodec::Mjpeg,
        None,
        None,
        None,
        1,
        false,
    )
    .expect("media plan");
    let report = ValidationReport::new(vec![ValidationCheck::new(
        "complete",
        true,
        "capture is closed",
    )
    .expect("check")])
    .expect("report");
    let candidate = ScanCandidate::new(
        CandidateId::from_material(b"candidate"),
        SourceRevisionClaim::Provisional(CandidateRevision::from_material(b"revision")),
        SourceKind::LocalFolder,
        SourceSchema::CompleteUnpublishedV6,
        "session-1".to_string(),
        locator,
        vec![claim],
        plan,
        SourceTrustVerdicts::pending_unsigned(),
        CandidateReadiness::ReadyUnsignedRequiresPolicy,
        report,
        None,
    )
    .expect("candidate");
    let candidate_revision = match candidate.revision_claim() {
        SourceRevisionClaim::Provisional(revision) => revision.clone(),
        SourceRevisionClaim::Published(_) => panic!("test candidate must be provisional"),
    };
    let mismatched_receipt = UnsignedSourceAdmissionReceipt::new(
        "receipt-other-candidate",
        CandidateId::from_material(b"other-candidate"),
        candidate.locator().media_generation_id().cloned(),
        candidate_revision.clone(),
        "policy-v1",
        "now",
    )
    .expect("receipt");
    assert!(matches!(
        SourceRecording::admit_unsigned(candidate.clone(), Some(mismatched_receipt)),
        Err(AdmissionError::UnsignedAdmissionReceiptMismatch(_))
    ));
    let receipt = UnsignedSourceAdmissionReceipt::new(
        "receipt",
        candidate.id().clone(),
        candidate.locator().media_generation_id().cloned(),
        candidate_revision,
        "policy-v1",
        "now",
    )
    .expect("receipt");
    let source = SourceRecording::admit_unsigned(candidate, Some(receipt)).expect("admission");
    let policy = ImportPolicy::new(UnsignedImportPolicy::RequireAdmissionReceipt, 10, 1);
    let spec = crate::ingest::ImportSpec::new(crate::ingest::ImportJobId::new(), source, policy)
        .expect("spec");
    let mut job = ImportJob::new(spec);
    let decision = job.decide(ImportCommand::Start);
    assert!(matches!(
        decision.effects().first(),
        Some(ImportEffect::PersistSnapshot)
    ));
    assert!(matches!(
        decision.effects().get(1),
        Some(ImportEffect::StartPreflight { .. })
    ));
}
