use serde::{Deserialize, Serialize};

use crate::ingest::SourceContentRevision;
use crate::media_store::{LibraryImportReceipt, MediaStore, MediaStoreError};

use super::model::SourceLocalVerified;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptPortError {
    #[error("receipt evidence is corrupt: {detail}")]
    Corrupt { detail: String },
    #[error("receipt evidence is temporarily unavailable: {detail}")]
    Unavailable { detail: String },
}

/// Long-lived receipt lookup, independent of import-job retention.
pub trait ImportReceiptLookup {
    fn find_by_source(
        &self,
        source_identity: &str,
        source_revision: &SourceContentRevision,
    ) -> Result<Option<LibraryImportReceipt>, ReceiptPortError>;
}

impl ImportReceiptLookup for MediaStore {
    fn find_by_source(
        &self,
        source_identity: &str,
        source_revision: &SourceContentRevision,
    ) -> Result<Option<LibraryImportReceipt>, ReceiptPortError> {
        self.import_receipt_by_source(source_identity, source_revision.as_str())
            .map_err(map_store_error)
    }
}

impl ImportReceiptLookup for &MediaStore {
    fn find_by_source(
        &self,
        source_identity: &str,
        source_revision: &SourceContentRevision,
    ) -> Result<Option<LibraryImportReceipt>, ReceiptPortError> {
        (*self).find_by_source(source_identity, source_revision)
    }
}

/// Evidence obtained by re-reading the sealed local tree and its durable
/// commit marker. A row existing in SQLite is not enough for deduplication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevalidatedImportEvidence {
    pub source_identity: String,
    pub source_revision: String,
    pub sealed_inventory_digest: String,
    pub provenance: serde_json::Value,
    pub local_path: String,
    pub commit_receipt: serde_json::Value,
}

/// Filesystem adapter used to revalidate a durable import receipt without
/// giving the domain layer direct filesystem authority.
pub trait LocalImportEvidenceReader {
    fn reread(
        &self,
        receipt: &LibraryImportReceipt,
    ) -> Result<Option<RevalidatedImportEvidence>, ReceiptPortError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum ReceiptEvidenceFailure {
    LocalEvidenceMissing,
    EvidenceMismatch { fields: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ImportDeduplication {
    NotImported,
    AlreadyImported {
        receipt: LibraryImportReceipt,
    },
    RepairRequired {
        receipt: LibraryImportReceipt,
        failure: ReceiptEvidenceFailure,
    },
}

/// Resolves a candidate against the durable import fence.
///
/// Acquisition location is not an input. The same source reached through
/// LAN, card, or a selected local folder therefore shares this decision.
/// `AlreadyImported` is returned only after all immutable local evidence has
/// been re-read and matched to the durable receipt.
pub fn resolve_import<L, E>(
    receipts: &L,
    evidence_reader: &E,
    source_identity: &str,
    source_revision: &SourceContentRevision,
) -> Result<ImportDeduplication, ReceiptPortError>
where
    L: ImportReceiptLookup,
    E: LocalImportEvidenceReader,
{
    let Some(receipt) = receipts.find_by_source(source_identity, source_revision)? else {
        return Ok(ImportDeduplication::NotImported);
    };
    if receipt.source_identity != source_identity
        || receipt.source_revision != source_revision.as_str()
    {
        return Err(ReceiptPortError::Corrupt {
            detail: "receipt lookup returned a different source identity/revision".to_string(),
        });
    }
    SourceLocalVerified::from_import_receipt(&receipt).map_err(|error| {
        ReceiptPortError::Corrupt {
            detail: format!("durable import receipt failed structural validation: {error}"),
        }
    })?;
    let Some(evidence) = evidence_reader.reread(&receipt)? else {
        return Ok(ImportDeduplication::RepairRequired {
            receipt,
            failure: ReceiptEvidenceFailure::LocalEvidenceMissing,
        });
    };

    let mut mismatches = Vec::new();
    if evidence.source_identity != receipt.source_identity {
        mismatches.push("source_identity".to_string());
    }
    if evidence.source_revision != receipt.source_revision {
        mismatches.push("source_revision".to_string());
    }
    if evidence.sealed_inventory_digest != receipt.sealed_inventory_digest {
        mismatches.push("sealed_inventory_digest".to_string());
    }
    if evidence.provenance != receipt.provenance {
        mismatches.push("provenance".to_string());
    }
    if evidence.local_path != receipt.local_path {
        mismatches.push("local_path".to_string());
    }
    if evidence.commit_receipt != receipt.commit_receipt {
        mismatches.push("commit_receipt".to_string());
    }
    if mismatches.is_empty() {
        Ok(ImportDeduplication::AlreadyImported { receipt })
    } else {
        Ok(ImportDeduplication::RepairRequired {
            receipt,
            failure: ReceiptEvidenceFailure::EvidenceMismatch { fields: mismatches },
        })
    }
}

fn map_store_error(error: MediaStoreError) -> ReceiptPortError {
    let detail = error.to_string();
    match error {
        MediaStoreError::Corrupt { .. }
        | MediaStoreError::Serialization(_)
        | MediaStoreError::Migration { .. }
        | MediaStoreError::UnsupportedSchemaVersion { .. } => ReceiptPortError::Corrupt { detail },
        _ => ReceiptPortError::Unavailable { detail },
    }
}
