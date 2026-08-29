//! Bucket Publication v4 producer and admission-consumer contract.
//!
//! The module is intentionally pure: it validates exact local JSON, builds
//! deterministic object keys and marker bytes, selects the only acknowledgement
//! under the marker's evidence authority, and validates its bounded readback.
//! Network I/O and durable upload receipts stay in the composition root.

use std::sync::OnceLock;

use chrono::DateTime;
use jsonschema::Draft;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use ylx_transfer_core::library::object_store_port::{
    sha256_of, DigestProof, ListedObject, ObjectKey, ObjectListPage, ObjectReadback, SourceSha256,
    VerifiedObjectReceipt,
};
use ylx_transfer_core::publication::parse_strict_json;

const SOURCE_SCHEMA_JSON: &str =
    include_str!("../../../contracts/schemas/ylx-device-session-v2.schema.json");
const RECEIPT_SCHEMA_JSON: &str =
    include_str!("../../../contracts/schemas/ylx-derived-media-receipt-v1.schema.json");
const PUBLICATION_SCHEMA_JSON: &str =
    include_str!("../../../contracts/schemas/ylx-bucket-publication-v4.schema.json");
const ADMISSION_SCHEMA_JSON: &str =
    include_str!("../../../contracts/schemas/ylx-bucket-publication-admission-v1.schema.json");

pub(super) const MAX_PUBLICATION_JSON_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct DerivedPublicationInput<'a> {
    pub prefix: &'a str,
    pub source_device_id: &'a str,
    pub source_device_label: &'a str,
    pub source_manifest_id: &'a str,
    pub source_session_id: &'a str,
    pub source_volume_id: &'a str,
    pub source_manifest_bytes: &'a [u8],
    pub source_manifest_sha256: SourceSha256,
    pub receipt_id: &'a str,
    pub receipt_bytes: &'a [u8],
    pub receipt_sha256: SourceSha256,
    pub output_artifact_id: &'a str,
    pub output_bytes: u64,
    pub output_sha256: SourceSha256,
    pub published_at: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DerivedPublicationPlan {
    pub publication_id: String,
    pub source_manifest_key: ObjectKey,
    pub receipt_key: ObjectKey,
    pub output_key: ObjectKey,
    pub marker_key: ObjectKey,
    pub marker_bytes: Vec<u8>,
    pub marker_sha256: SourceSha256,
    pub published_at: String,
    pub admission_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AdmissionError {
    Invalid(String),
    Rejected(String),
}

impl DerivedPublicationPlan {
    pub fn build(input: &DerivedPublicationInput<'_>) -> Result<Self, String> {
        let source_value = strict_document(input.source_manifest_bytes, "source manifest")?;
        validate_source_manifest_schema(&source_value)?;
        let source: SourceDocument = serde_json::from_value(source_value)
            .map_err(|error| format!("source manifest identity is invalid: {error}"))?;
        if source.schema != "ylx.device-session.v2"
            || source.manifest_id != input.source_manifest_id
            || source.session_id != input.source_session_id
            || source.volume_id != input.source_volume_id
            || source.device.device_id != input.source_device_id
            || source.device.device_label != input.source_device_label
            || sha256_of(input.source_manifest_bytes) != input.source_manifest_sha256
        {
            return Err("source manifest bytes differ from the publication input".to_string());
        }

        let receipt_value = strict_document(input.receipt_bytes, "derived media receipt")?;
        validate_schema(&receipt_value, receipt_validator(), "derived media receipt")?;
        let receipt: ReceiptDocument = serde_json::from_value(receipt_value)
            .map_err(|error| format!("derived media receipt identity is invalid: {error}"))?;
        if receipt.schema != "ylx.derived-media-receipt.v1"
            || receipt.receipt_id != input.receipt_id
            || receipt.source_manifest.schema != source.schema
            || receipt.source_manifest.manifest_id != source.manifest_id
            || receipt.source_manifest.session_id != source.session_id
            || receipt.source_manifest.volume_id != source.volume_id
            || receipt.source_manifest.bytes != input.source_manifest_bytes.len() as u64
            || receipt.source_manifest.sha256 != input.source_manifest_sha256.to_hex()
            || receipt.output.artifact_id != input.output_artifact_id
            || receipt.output.artifact_id != receipt.output.sha256
            || receipt.output.bytes != input.output_bytes
            || receipt.output.sha256 != input.output_sha256.to_hex()
            || receipt.canonicalization.committed_at != input.published_at
            || sha256_of(input.receipt_bytes) != input.receipt_sha256
        {
            return Err(
                "derived media receipt does not close over the publication input".to_string(),
            );
        }
        DateTime::parse_from_rfc3339(input.published_at)
            .map_err(|error| format!("publication timestamp is invalid: {error}"))?;

        // A canonical derived receipt identifies exactly one publication.
        // Reusing its UUIDv7 keeps ordinary retries byte-identical without a
        // second mutable local id journal.
        require_uuid_version(input.receipt_id, 7, "receipt/publication id")?;
        let publication_id = input.receipt_id.to_string();
        let root = object_root(
            input.prefix,
            input.source_device_id,
            input.source_session_id,
            &publication_id,
        );
        let source_manifest_key = ObjectKey(format!(
            "{root}/f-{}",
            input.source_manifest_sha256.to_hex()
        ));
        let receipt_key = ObjectKey(format!("{root}/f-{}", input.receipt_sha256.to_hex()));
        let output_key = ObjectKey(format!("{root}/f-{}", input.output_sha256.to_hex()));
        let marker_key = ObjectKey(format!("{root}/__ylx_evidence__/publication.json"));

        let marker = PublicationMarker {
            schema: "ylx.bucket-publication.v4",
            publication_id: &publication_id,
            publication_kind: "client-derived",
            sealed: true,
            published_at: input.published_at,
            source_device: MarkerSourceDevice {
                device_id: input.source_device_id,
                device_label: input.source_device_label,
            },
            publication_object_key: &marker_key.0,
            assets: [
                MarkerAsset::SourceManifest {
                    role: "source.manifest",
                    schema: "ylx.device-session.v2",
                    manifest_id: input.source_manifest_id,
                    session_id: input.source_session_id,
                    volume_id: input.source_volume_id,
                    object_key: &source_manifest_key.0,
                    media_type: "application/json",
                    bytes: input.source_manifest_bytes.len() as u64,
                    sha256: input.source_manifest_sha256.to_hex(),
                },
                MarkerAsset::DerivedReceipt {
                    role: "media.derived-receipt",
                    schema: "ylx.derived-media-receipt.v1",
                    receipt_id: input.receipt_id,
                    object_key: &receipt_key.0,
                    media_type: "application/json",
                    bytes: input.receipt_bytes.len() as u64,
                    sha256: input.receipt_sha256.to_hex(),
                },
                MarkerAsset::DerivedOutput {
                    role: "media.derived",
                    artifact_id: input.output_artifact_id,
                    object_key: &output_key.0,
                    media_type: "video/mp4",
                    bytes: input.output_bytes,
                    sha256: input.output_sha256.to_hex(),
                },
            ],
            provenance: MarkerProvenance {
                derived_authorship: "openaria-bridge-desktop",
                source_manifest_signature: "not-declared-by-device-session-v2",
                device_signature_inheritance: "forbidden",
                derived_output_signature: "not-device-signed",
            },
        };
        let mut marker_bytes = serde_json::to_vec(&marker)
            .map_err(|error| format!("cannot serialize Bucket Publication v4: {error}"))?;
        marker_bytes.push(b'\n');
        let marker_value = strict_document(&marker_bytes, "Bucket Publication v4 marker")?;
        validate_schema(
            &marker_value,
            publication_validator(),
            "Bucket Publication v4 marker",
        )?;
        let marker_sha256 = sha256_of(&marker_bytes);
        let admission_prefix = admission_evidence_prefix(&marker_key)?;
        Ok(Self {
            publication_id,
            source_manifest_key,
            receipt_key,
            output_key,
            marker_key,
            marker_bytes,
            marker_sha256,
            published_at: input.published_at.to_string(),
            admission_prefix,
        })
    }

    pub fn verify_marker_readback(
        &self,
        readback: &ObjectReadback,
    ) -> Result<VerifiedObjectReceipt, String> {
        verify_exact_json_readback(
            readback,
            &self.marker_key,
            &self.marker_bytes,
            self.marker_sha256,
        )
    }

    pub fn select_admission_candidate<'a>(
        &self,
        page: &'a ObjectListPage,
    ) -> Result<Option<&'a ListedObject>, AdmissionError> {
        if page.is_truncated || page.objects.len() > 1 {
            return Err(AdmissionError::Invalid(
                "publication completion requires exactly one acknowledgement".to_string(),
            ));
        }
        let Some(candidate) = page.objects.first() else {
            return Ok(None);
        };
        if candidate.size_bytes == 0
            || candidate.etag.trim().is_empty()
            || !admission_key_belongs_to_marker(&self.marker_key, &candidate.key)
        {
            return Err(AdmissionError::Invalid(
                "admission candidate is outside the exact publication evidence authority"
                    .to_string(),
            ));
        }
        Ok(Some(candidate))
    }

    pub fn verify_admission(
        &self,
        candidate: &ListedObject,
        readback: &ObjectReadback,
    ) -> Result<VerifiedObjectReceipt, AdmissionError> {
        if readback.key != candidate.key
            || readback.bytes.len() as u64 != candidate.size_bytes
            || readback.etag != candidate.etag
        {
            return Err(AdmissionError::Invalid(
                "admission readback key/bytes differ from the listed candidate".to_string(),
            ));
        }
        require_json_content_type(readback).map_err(AdmissionError::Invalid)?;
        let value = strict_document(&readback.bytes, "publication admission")
            .map_err(AdmissionError::Invalid)?;
        validate_schema(&value, admission_validator(), "publication admission")
            .map_err(AdmissionError::Invalid)?;
        let admission: AdmissionDocument = serde_json::from_value(value).map_err(|error| {
            AdmissionError::Invalid(format!("admission shape is invalid: {error}"))
        })?;
        require_uuid_version(&admission.admission_id, 7, "admission id")
            .map_err(AdmissionError::Invalid)?;
        let expected_admission_key =
            admission_object_key(&self.marker_key, &admission.admission_id)
                .map_err(AdmissionError::Invalid)?;
        let marker_sha256 = self.marker_sha256.to_hex();
        if admission.schema != "ylx.bucket-publication-admission.v1"
            || admission.publication_id != self.publication_id
            || admission.publication_schema != "ylx.bucket-publication.v4"
            || admission.marker.object_key != self.marker_key.0
            || admission.marker.bytes != self.marker_bytes.len() as u64
            || admission.marker.sha256 != marker_sha256
            || admission.consumer.name != "egoview-console"
            || admission.consumer.version.trim().is_empty()
            || admission.consumer.build.commit.len() != 40
            || admission.consumer.build.artifact_sha256.len() != 64
            || admission.admission_object_key != expected_admission_key.0
            || readback.key != expected_admission_key
        {
            return Err(AdmissionError::Invalid(
                "admission does not bind the exact publication marker".to_string(),
            ));
        }
        let admitted_at =
            DateTime::parse_from_rfc3339(&admission.admitted_at).map_err(|error| {
                AdmissionError::Invalid(format!("admission timestamp is invalid: {error}"))
            })?;
        let published_at = DateTime::parse_from_rfc3339(&self.published_at).map_err(|error| {
            AdmissionError::Invalid(format!("publication timestamp is invalid: {error}"))
        })?;
        if admitted_at < published_at {
            return Err(AdmissionError::Invalid(
                "admission admitted_at precedes publication published_at".to_string(),
            ));
        }
        if admission.verdict == "rejected" {
            let detail = admission
                .diagnostics
                .iter()
                .map(|item| format!("{}: {}", item.code, item.summary))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(AdmissionError::Rejected(detail));
        }
        if admission.verdict != "admitted" || !admission.diagnostics.is_empty() {
            return Err(AdmissionError::Invalid(
                "admission verdict is not the closed admitted state".to_string(),
            ));
        }
        let digest = sha256_of(&readback.bytes);
        if readback
            .source_sha256_metadata
            .is_some_and(|metadata| metadata != digest)
        {
            return Err(AdmissionError::Invalid(
                "admission metadata digest differs from its bytes".to_string(),
            ));
        }
        Ok(VerifiedObjectReceipt {
            key: readback.key.clone(),
            etag: readback.etag.clone(),
            version_id: readback.version_id.clone(),
            size_bytes: readback.bytes.len() as u64,
            source_sha256: digest,
            digest_proof: DigestProof::StreamedReadback,
        })
    }
}

pub(super) fn admission_evidence_prefix(marker_key: &ObjectKey) -> Result<String, String> {
    let evidence_authority = marker_key
        .0
        .strip_suffix("publication.json")
        .ok_or_else(|| "Bucket Publication v4 marker key has an invalid suffix".to_string())?;
    if !evidence_authority.ends_with("/__ylx_evidence__/") {
        return Err("Bucket Publication v4 marker key has an invalid authority".to_string());
    }
    Ok(format!("{evidence_authority}admission-"))
}

pub(super) fn admission_object_key(
    marker_key: &ObjectKey,
    admission_id: &str,
) -> Result<ObjectKey, String> {
    require_uuid_version(admission_id, 7, "admission id")?;
    Ok(ObjectKey(format!(
        "{}{}.json",
        admission_evidence_prefix(marker_key)?,
        admission_id
    )))
}

pub(super) fn admission_key_belongs_to_marker(
    marker_key: &ObjectKey,
    candidate_key: &ObjectKey,
) -> bool {
    let Ok(prefix) = admission_evidence_prefix(marker_key) else {
        return false;
    };
    let Some(admission_id) = candidate_key
        .0
        .strip_prefix(&prefix)
        .and_then(|leaf| leaf.strip_suffix(".json"))
    else {
        return false;
    };
    admission_object_key(marker_key, admission_id).is_ok_and(|expected| expected == *candidate_key)
}

fn verify_exact_json_readback(
    readback: &ObjectReadback,
    expected_key: &ObjectKey,
    expected_bytes: &[u8],
    expected_sha256: SourceSha256,
) -> Result<VerifiedObjectReceipt, String> {
    if &readback.key != expected_key
        || readback.bytes != expected_bytes
        || sha256_of(&readback.bytes) != expected_sha256
        || readback.etag.trim().is_empty()
        || readback
            .source_sha256_metadata
            .is_some_and(|metadata| metadata != expected_sha256)
    {
        return Err("immutable marker changed during exact readback".to_string());
    }
    require_json_content_type(readback)?;
    Ok(VerifiedObjectReceipt {
        key: readback.key.clone(),
        etag: readback.etag.clone(),
        version_id: readback.version_id.clone(),
        size_bytes: readback.bytes.len() as u64,
        source_sha256: expected_sha256,
        digest_proof: DigestProof::StreamedReadback,
    })
}

fn require_json_content_type(readback: &ObjectReadback) -> Result<(), String> {
    let media_type = readback
        .content_type
        .as_deref()
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if media_type == Some("application/json") {
        Ok(())
    } else {
        Err("publication object is not application/json".to_string())
    }
}

fn object_root(prefix: &str, device_id: &str, session_id: &str, publication_id: &str) -> String {
    let prefix = prefix.trim().trim_matches('/');
    if prefix.is_empty() {
        format!("{device_id}/{session_id}/{publication_id}")
    } else {
        format!("{prefix}/{device_id}/{session_id}/{publication_id}")
    }
}

fn strict_document(bytes: &[u8], label: &str) -> Result<Value, String> {
    let value = parse_strict_json(bytes).map_err(|error| format!("{label} is invalid: {error}"))?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(format!("{label} is not a JSON object"))
    }
}

fn validate_schema(
    value: &Value,
    validator: &jsonschema::Validator,
    label: &str,
) -> Result<(), String> {
    let errors = validator
        .iter_errors(value)
        .take(4)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{label} violates its exact schema: {}",
            errors.join("; ")
        ))
    }
}

pub(super) fn validate_source_manifest_schema(value: &Value) -> Result<(), String> {
    validate_schema(value, source_validator(), "source manifest")
}

fn compile_schema(raw: &str) -> jsonschema::Validator {
    let value: Value = serde_json::from_str(raw).expect("vendored publication schema is JSON");
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .build(&value)
        .expect("vendored publication schema compiles")
}

fn source_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| compile_schema(SOURCE_SCHEMA_JSON))
}

fn receipt_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| compile_schema(RECEIPT_SCHEMA_JSON))
}

fn publication_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| compile_schema(PUBLICATION_SCHEMA_JSON))
}

fn admission_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| compile_schema(ADMISSION_SCHEMA_JSON))
}

fn require_uuid_version(raw: &str, version: usize, label: &str) -> Result<(), String> {
    let parsed = Uuid::parse_str(raw).map_err(|error| format!("{label} is invalid: {error}"))?;
    if parsed.get_version_num() == version && raw == parsed.to_string() {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase UUIDv{version}"))
    }
}

#[derive(Debug, Deserialize)]
struct SourceDocument {
    schema: String,
    manifest_id: String,
    session_id: String,
    volume_id: String,
    device: SourceDevice,
}

#[derive(Debug, Deserialize)]
struct SourceDevice {
    device_id: String,
    device_label: String,
}

#[derive(Debug, Deserialize)]
struct ReceiptDocument {
    schema: String,
    receipt_id: String,
    source_manifest: ReceiptSourceManifest,
    output: ReceiptOutput,
    canonicalization: ReceiptCanonicalization,
}

#[derive(Debug, Deserialize)]
struct ReceiptSourceManifest {
    schema: String,
    manifest_id: String,
    session_id: String,
    volume_id: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ReceiptOutput {
    artifact_id: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ReceiptCanonicalization {
    committed_at: String,
}

#[derive(Debug, Serialize)]
struct PublicationMarker<'a> {
    schema: &'static str,
    publication_id: &'a str,
    publication_kind: &'static str,
    sealed: bool,
    published_at: &'a str,
    source_device: MarkerSourceDevice<'a>,
    publication_object_key: &'a str,
    assets: [MarkerAsset<'a>; 3],
    provenance: MarkerProvenance,
}

#[derive(Debug, Serialize)]
struct MarkerSourceDevice<'a> {
    device_id: &'a str,
    device_label: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum MarkerAsset<'a> {
    SourceManifest {
        role: &'static str,
        schema: &'static str,
        manifest_id: &'a str,
        session_id: &'a str,
        volume_id: &'a str,
        object_key: &'a str,
        media_type: &'static str,
        bytes: u64,
        sha256: String,
    },
    DerivedReceipt {
        role: &'static str,
        schema: &'static str,
        receipt_id: &'a str,
        object_key: &'a str,
        media_type: &'static str,
        bytes: u64,
        sha256: String,
    },
    DerivedOutput {
        role: &'static str,
        artifact_id: &'a str,
        object_key: &'a str,
        media_type: &'static str,
        bytes: u64,
        sha256: String,
    },
}

#[derive(Debug, Serialize)]
struct MarkerProvenance {
    derived_authorship: &'static str,
    source_manifest_signature: &'static str,
    device_signature_inheritance: &'static str,
    derived_output_signature: &'static str,
}

#[derive(Debug, Deserialize)]
struct AdmissionDocument {
    schema: String,
    admission_id: String,
    publication_id: String,
    publication_schema: String,
    marker: AdmissionMarker,
    consumer: AdmissionConsumer,
    admission_object_key: String,
    admitted_at: String,
    verdict: String,
    diagnostics: Vec<AdmissionDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct AdmissionMarker {
    object_key: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct AdmissionConsumer {
    name: String,
    version: String,
    build: AdmissionConsumerBuild,
}

#[derive(Debug, Deserialize)]
struct AdmissionConsumerBuild {
    commit: String,
    artifact_sha256: String,
}

#[derive(Debug, Deserialize)]
struct AdmissionDiagnostic {
    code: String,
    summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &[u8] = include_bytes!(
        "../../../contracts/fixtures/valid/ylx-device-session-v2.audio-recorded-multi-segment.json"
    );
    const RECEIPT: &[u8] =
        include_bytes!("../../../contracts/fixtures/valid/ylx-derived-media-receipt-v1.json");
    const ADMITTED_ADMISSION: &[u8] = include_bytes!(
        "../../../contracts/fixtures/valid/ylx-bucket-publication-admission-v1.admitted.json"
    );
    const REJECTED_ADMISSION: &[u8] = include_bytes!(
        "../../../contracts/fixtures/valid/ylx-bucket-publication-admission-v1.rejected.json"
    );
    const TEST_ADMISSION_ID: &str = "019a0030-0000-7a1b-8c2d-3e4f50617283";

    fn plan() -> DerivedPublicationPlan {
        let source: Value = serde_json::from_slice(SOURCE).unwrap();
        let receipt: Value = serde_json::from_slice(RECEIPT).unwrap();
        let output_sha = receipt["output"]["sha256"].as_str().unwrap();
        DerivedPublicationPlan::build(&DerivedPublicationInput {
            prefix: "synthetic/qualification/ylx-transfer",
            source_device_id: source["device"]["device_id"].as_str().unwrap(),
            source_device_label: source["device"]["device_label"].as_str().unwrap(),
            source_manifest_id: source["manifest_id"].as_str().unwrap(),
            source_session_id: source["session_id"].as_str().unwrap(),
            source_volume_id: source["volume_id"].as_str().unwrap(),
            source_manifest_bytes: SOURCE,
            source_manifest_sha256: sha256_of(SOURCE),
            receipt_id: receipt["receipt_id"].as_str().unwrap(),
            receipt_bytes: RECEIPT,
            receipt_sha256: sha256_of(RECEIPT),
            output_artifact_id: output_sha,
            output_bytes: receipt["output"]["bytes"].as_u64().unwrap(),
            output_sha256: SourceSha256::from_hex(output_sha).unwrap(),
            published_at: receipt["canonicalization"]["committed_at"]
                .as_str()
                .unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn vendored_schema_identities_match_score() {
        assert_eq!(
            sha256_of(SOURCE_SCHEMA_JSON.as_bytes()).to_hex(),
            "7de77a092152cb68d57fc9e46dcc3024fe521dbcf5961999cf0ac887186a59c8"
        );
        assert_eq!(
            sha256_of(RECEIPT_SCHEMA_JSON.as_bytes()).to_hex(),
            "dff40539d8905f8f28f5cf67f5fdf0415f212a68e6dd21cdfb528984109aa695"
        );
        assert_eq!(
            sha256_of(PUBLICATION_SCHEMA_JSON.as_bytes()).to_hex(),
            "f869422c563df18efe43d2d0b0c51e801458127f1660b257f84f69e3bd8c5047"
        );
        assert_eq!(
            sha256_of(ADMISSION_SCHEMA_JSON.as_bytes()).to_hex(),
            "6b8df6ef5ba3eb920eb70614d629bf68679541732b7450372632066aea4bdf8d"
        );
        assert_eq!(
            sha256_of(D053_CORPUS.as_bytes()).to_hex(),
            "6321ac000c22dbaf9331f8cc3f74753ecf42773e376e63c2298d4b90ba29c625"
        );
        let corpus: Value = serde_json::from_str(D053_CORPUS).unwrap();
        assert_eq!(corpus["cases"].as_array().unwrap().len(), 24);
        assert_eq!(corpus["admission_cases"].as_array().unwrap().len(), 17);
        assert_eq!(corpus["completion_cases"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn marker_is_schema_valid_stable_and_derived_only() {
        let first = plan();
        let second = plan();
        assert_eq!(first, second);
        let marker: Value = serde_json::from_slice(&first.marker_bytes).unwrap();
        assert_eq!(marker["publication_kind"], "client-derived");
        assert_eq!(marker["assets"].as_array().unwrap().len(), 3);
        assert!(first
            .marker_key
            .0
            .ends_with("/__ylx_evidence__/publication.json"));
        assert!(!String::from_utf8_lossy(&first.marker_bytes).contains("video.left"));
        assert_eq!(
            marker["provenance"]["device_signature_inheritance"],
            "forbidden"
        );
        assert_eq!(
            marker["provenance"]["derived_output_signature"],
            "not-device-signed"
        );
    }

    #[test]
    fn exact_admission_is_required() {
        let plan = plan();
        let admission_key = admission_object_key(&plan.marker_key, TEST_ADMISSION_ID).unwrap();
        let document = serde_json::json!({
            "schema": "ylx.bucket-publication-admission.v1",
            "admission_id": TEST_ADMISSION_ID,
            "publication_id": plan.publication_id,
            "publication_schema": "ylx.bucket-publication.v4",
            "marker": {
                "object_key": plan.marker_key.0,
                "bytes": plan.marker_bytes.len(),
                "sha256": plan.marker_sha256.to_hex()
            },
            "consumer": {
                "name": "egoview-console",
                "version": "0.1.0",
                "build": {
                    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "artifact_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }
            },
            "admission_object_key": admission_key.0,
            "admitted_at": "2026-08-28T10:12:00Z",
            "verdict": "admitted",
            "diagnostics": []
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        let digest = sha256_of(&bytes);
        let candidate = ListedObject {
            key: admission_key.clone(),
            size_bytes: bytes.len() as u64,
            etag: "admission-etag".to_string(),
        };
        let readback = ObjectReadback {
            key: admission_key,
            bytes,
            etag: "admission-etag".to_string(),
            version_id: Some("v1".to_string()),
            source_sha256_metadata: Some(digest),
            content_type: Some("application/json".to_string()),
        };
        let receipt = plan.verify_admission(&candidate, &readback).unwrap();
        assert_eq!(receipt.source_sha256, digest);

        let mut drifted_candidate = candidate;
        drifted_candidate.etag = "replacement-etag".to_string();
        assert!(matches!(
            plan.verify_admission(&drifted_candidate, &readback),
            Err(AdmissionError::Invalid(_))
        ));
    }

    #[test]
    fn rejected_or_extra_field_admission_never_completes() {
        let plan = plan();
        let admission_key = admission_object_key(&plan.marker_key, TEST_ADMISSION_ID).unwrap();
        let mut value: Value = serde_json::from_slice(ADMITTED_ADMISSION).unwrap();
        value["publication_id"] = Value::String(plan.publication_id.clone());
        value["admission_id"] = Value::String(TEST_ADMISSION_ID.to_string());
        value["admission_object_key"] = Value::String(admission_key.0.clone());
        value["marker"] = serde_json::json!({
            "object_key": plan.marker_key.0,
            "bytes": plan.marker_bytes.len(),
            "sha256": plan.marker_sha256.to_hex()
        });
        value["verdict"] = Value::String("rejected".to_string());
        value["diagnostics"] = serde_json::json!([{
            "code": "timeline_verification_failed",
            "summary": "timeline failed"
        }]);
        let bytes = serde_json::to_vec(&value).unwrap();
        let candidate = ListedObject {
            key: admission_key.clone(),
            size_bytes: bytes.len() as u64,
            etag: "etag".to_string(),
        };
        let error = plan
            .verify_admission(
                &candidate,
                &ObjectReadback {
                    key: admission_key.clone(),
                    bytes,
                    etag: "etag".to_string(),
                    version_id: None,
                    source_sha256_metadata: None,
                    content_type: Some("application/json".to_string()),
                },
            )
            .unwrap_err();
        assert!(matches!(error, AdmissionError::Rejected(_)));

        value["unexpected"] = Value::Bool(true);
        let bytes = serde_json::to_vec(&value).unwrap();
        let candidate = ListedObject {
            key: admission_key.clone(),
            size_bytes: bytes.len() as u64,
            etag: "etag".to_string(),
        };
        let error = plan
            .verify_admission(
                &candidate,
                &ObjectReadback {
                    key: admission_key,
                    bytes,
                    etag: "etag".to_string(),
                    version_id: None,
                    source_sha256_metadata: None,
                    content_type: Some("application/json".to_string()),
                },
            )
            .unwrap_err();
        assert!(matches!(error, AdmissionError::Invalid(_)));
    }

    const PUBLICATION: &[u8] =
        include_bytes!("../../../contracts/fixtures/valid/ylx-bucket-publication-v4.json");
    const D053_CORPUS: &str =
        include_str!("../../../contracts/fixtures/corpora/derived-bucket-publication-v4.json");

    fn score_plan() -> DerivedPublicationPlan {
        let marker: Value = serde_json::from_slice(PUBLICATION).unwrap();
        let assets = marker["assets"].as_array().unwrap();
        let key_for = |role: &str| {
            ObjectKey(
                assets.iter().find(|asset| asset["role"] == role).unwrap()["object_key"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        };
        let marker_key = ObjectKey(
            marker["publication_object_key"]
                .as_str()
                .unwrap()
                .to_string(),
        );
        DerivedPublicationPlan {
            publication_id: marker["publication_id"].as_str().unwrap().to_string(),
            source_manifest_key: key_for("source.manifest"),
            receipt_key: key_for("media.derived-receipt"),
            output_key: key_for("media.derived"),
            admission_prefix: admission_evidence_prefix(&marker_key).unwrap(),
            marker_key,
            marker_bytes: PUBLICATION.to_vec(),
            marker_sha256: sha256_of(PUBLICATION),
            published_at: marker["published_at"].as_str().unwrap().to_string(),
        }
    }

    fn value_at_path_mut<'a>(mut value: &'a mut Value, path: &[Value]) -> &'a mut Value {
        for component in path {
            value = if let Some(field) = component.as_str() {
                value.get_mut(field).expect("corpus object path exists")
            } else {
                value
                    .get_mut(component.as_u64().expect("corpus array index") as usize)
                    .expect("corpus array path exists")
            };
        }
        value
    }

    fn mutate_admission(document: &mut Value, case: &Value) {
        let path = case["path"].as_array().expect("mutation path");
        match case["operation"].as_str().unwrap() {
            "replace-admission" => {
                *value_at_path_mut(document, path) = case["value"].clone();
            }
            "add-admission-field" => {
                value_at_path_mut(document, path)
                    .as_object_mut()
                    .expect("field target is an object")
                    .insert(
                        case["field"].as_str().unwrap().to_string(),
                        case["value"].clone(),
                    );
            }
            other => panic!("unexpected admission mutation {other}"),
        }
    }

    fn listed_candidate(observed: &Value) -> ListedObject {
        ListedObject {
            key: ObjectKey(observed["object_key"].as_str().unwrap().to_string()),
            size_bytes: observed["bytes"].as_u64().unwrap(),
            etag: "score-corpus-etag".to_string(),
        }
    }

    fn admission_readback(
        candidate: &ListedObject,
        bytes: Vec<u8>,
        observed_sha256: SourceSha256,
    ) -> ObjectReadback {
        ObjectReadback {
            key: candidate.key.clone(),
            bytes,
            etag: "score-corpus-etag".to_string(),
            version_id: Some("score-corpus-version".to_string()),
            source_sha256_metadata: Some(observed_sha256),
            content_type: Some("application/json".to_string()),
        }
    }

    fn verify_candidate(
        plan: &DerivedPublicationPlan,
        candidate: &ListedObject,
        readback: &ObjectReadback,
    ) -> Result<VerifiedObjectReceipt, AdmissionError> {
        let page = ObjectListPage {
            objects: vec![candidate.clone()],
            is_truncated: false,
        };
        let selected = plan.select_admission_candidate(&page)?.ok_or_else(|| {
            AdmissionError::Invalid("expected one acknowledgement candidate".to_string())
        })?;
        plan.verify_admission(selected, readback)
    }

    #[test]
    fn arbitrary_uuidv7_ack_keys_share_only_the_marker_authority() {
        let plan = score_plan();
        let admitted =
            admission_object_key(&plan.marker_key, "019a0030-0000-7a1b-8c2d-3e4f50617283").unwrap();
        let rejected =
            admission_object_key(&plan.marker_key, "019a0031-0000-7a1b-8c2d-3e4f50617283").unwrap();
        assert_ne!(admitted, rejected);
        assert!(admission_key_belongs_to_marker(&plan.marker_key, &admitted));
        assert!(admission_key_belongs_to_marker(&plan.marker_key, &rejected));
        assert!(admitted.0.starts_with(&plan.admission_prefix));
        assert!(!admission_key_belongs_to_marker(
            &plan.marker_key,
            &ObjectKey(admitted.0.replacen(
                "550e8400-e29b-41d4-a716-446655440000",
                "650e8400-e29b-41d4-a716-446655440000",
                1,
            )),
        ));

        let truncated = ObjectListPage {
            objects: vec![ListedObject {
                key: admitted,
                size_bytes: 1,
                etag: "etag".to_string(),
            }],
            is_truncated: true,
        };
        assert!(matches!(
            plan.select_admission_candidate(&truncated),
            Err(AdmissionError::Invalid(_))
        ));
    }

    #[test]
    fn d053_all_seventeen_ack_mutations_fail_closed() {
        let plan = score_plan();
        let corpus: Value = serde_json::from_str(D053_CORPUS).unwrap();
        let cases = corpus["admission_cases"].as_array().unwrap();
        assert_eq!(cases.len(), 17, "the vendored D-053 ack corpus drifted");

        for case in cases {
            let fixture_name = case["fixture"].as_str().unwrap();
            let fixture = match fixture_name {
                "admitted" => ADMITTED_ADMISSION,
                "rejected" => REJECTED_ADMISSION,
                other => panic!("unknown admission fixture {other}"),
            };
            let mut document: Value = serde_json::from_slice(fixture).unwrap();
            let operation = case["operation"].as_str().unwrap();
            let mut observed = corpus["observed_admissions"][fixture_name].clone();
            if operation == "replace-admission-observed" {
                observed.as_object_mut().unwrap().insert(
                    case["field"].as_str().unwrap().to_string(),
                    case["value"].clone(),
                );
            } else {
                mutate_admission(&mut document, case);
            }
            let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
            bytes.push(b'\n');
            if operation != "replace-admission-observed" {
                observed = serde_json::json!({
                    "object_key": document["admission_object_key"],
                    "bytes": bytes.len(),
                    "sha256": sha256_of(&bytes).to_hex(),
                });
            }
            let candidate = listed_candidate(&observed);
            let observed_sha256 =
                SourceSha256::from_hex(observed["sha256"].as_str().expect("observed SHA-256"))
                    .unwrap();
            let readback = admission_readback(&candidate, bytes, observed_sha256);
            let result = verify_candidate(&plan, &candidate, &readback);
            assert!(
                result.is_err(),
                "D-053 mutation {} unexpectedly completed",
                case["name"].as_str().unwrap()
            );
        }
    }

    fn corpus_completion(
        plan: &DerivedPublicationPlan,
        corpus: &Value,
        tokens: &[Value],
    ) -> Result<bool, AdmissionError> {
        let mut candidates = Vec::new();
        let mut readbacks = Vec::new();
        for token in tokens {
            let token = token.as_str().unwrap();
            let (candidate, readback) = match token {
                "admitted" => {
                    let candidate = listed_candidate(&corpus["observed_admissions"]["admitted"]);
                    let digest = SourceSha256::from_hex(
                        corpus["observed_admissions"]["admitted"]["sha256"]
                            .as_str()
                            .unwrap(),
                    )
                    .unwrap();
                    let readback =
                        admission_readback(&candidate, ADMITTED_ADMISSION.to_vec(), digest);
                    (candidate, Some(readback))
                }
                "admitted-unobserved" => (
                    listed_candidate(&corpus["observed_admissions"]["admitted"]),
                    None,
                ),
                "admitted-schema-drift" => {
                    let mut document: Value = serde_json::from_slice(ADMITTED_ADMISSION).unwrap();
                    document["completion_schema_drift"] = Value::Bool(true);
                    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
                    bytes.push(b'\n');
                    let candidate = ListedObject {
                        key: ObjectKey(
                            document["admission_object_key"]
                                .as_str()
                                .unwrap()
                                .to_string(),
                        ),
                        size_bytes: bytes.len() as u64,
                        etag: "score-corpus-etag".to_string(),
                    };
                    let readback = admission_readback(&candidate, bytes.clone(), sha256_of(&bytes));
                    (candidate, Some(readback))
                }
                "rejected" | "rejected-index-write-failed" => {
                    let mut document: Value = serde_json::from_slice(REJECTED_ADMISSION).unwrap();
                    if token == "rejected-index-write-failed" {
                        document["diagnostics"] = serde_json::json!([{
                            "code": "index_write_failed",
                            "summary": "Consumer index write did not complete."
                        }]);
                    }
                    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
                    bytes.push(b'\n');
                    let candidate = ListedObject {
                        key: ObjectKey(
                            document["admission_object_key"]
                                .as_str()
                                .unwrap()
                                .to_string(),
                        ),
                        size_bytes: bytes.len() as u64,
                        etag: "score-corpus-etag".to_string(),
                    };
                    let readback = admission_readback(&candidate, bytes.clone(), sha256_of(&bytes));
                    (candidate, Some(readback))
                }
                other => panic!("unknown completion acknowledgement token {other}"),
            };
            candidates.push(candidate);
            readbacks.push(readback);
        }
        let page = ObjectListPage {
            objects: candidates,
            is_truncated: false,
        };
        let Some(candidate) = plan.select_admission_candidate(&page)? else {
            return Ok(false);
        };
        let Some(readback) = readbacks.into_iter().next().flatten() else {
            return Ok(false);
        };
        match plan.verify_admission(candidate, &readback) {
            Ok(_) => Ok(true),
            Err(AdmissionError::Rejected(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn d053_all_completion_scenarios_match_score() {
        let plan = score_plan();
        let corpus: Value = serde_json::from_str(D053_CORPUS).unwrap();
        let cases = corpus["completion_cases"].as_array().unwrap();
        assert_eq!(
            cases.len(),
            8,
            "the vendored D-053 completion corpus drifted"
        );

        for case in cases {
            let tokens = case["acknowledgements"].as_array().unwrap();
            let actual = corpus_completion(&plan, &corpus, tokens);
            let expected = case["expected_complete"].as_bool().unwrap();
            let expects_error = !case["expected_error_keywords"]
                .as_array()
                .unwrap()
                .is_empty();
            if expects_error {
                let error = actual.expect_err("multiple/conflicting ack set must fail closed");
                assert!(matches!(error, AdmissionError::Invalid(_)));
                if tokens.len() != 1 {
                    assert!(
                        matches!(error, AdmissionError::Invalid(ref detail) if detail.contains("exactly one acknowledgement")),
                        "unexpected completion error for {}: {error:?}",
                        case["name"].as_str().unwrap(),
                    );
                }
            } else {
                assert_eq!(
                    actual.unwrap(),
                    expected,
                    "completion mismatch for {}",
                    case["name"].as_str().unwrap(),
                );
            }
        }
    }
}
