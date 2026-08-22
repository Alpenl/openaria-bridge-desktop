use rusqlite::{OptionalExtension, Transaction};

use crate::ingest::{ImportJobId, LocalSourceReceipt};
use crate::media_pipeline::LocalDerivedReceipt;

use super::error::MediaStoreError;
use super::model::{DerivedReceipt, LibraryImportReceipt, ReceiptWriteOutcome, SourceReceipt};
use super::store::{require_non_empty, require_sha256, MediaStore};

type SourceReceiptRow = (String, String, String, String, String, String, String);
type DerivedReceiptRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

impl MediaStore {
    /// Typed adapter from the ingest owner's sealed source receipt to the
    /// repository's durable source and duplicate-import projections.
    pub fn record_local_source_import(
        &mut self,
        receipt_id: &str,
        import_job_id: &ImportJobId,
        source_identity: &str,
        local: &LocalSourceReceipt,
    ) -> Result<ReceiptWriteOutcome<LibraryImportReceipt>, MediaStoreError> {
        let (source, import) =
            local_source_receipt_rows(receipt_id, import_job_id, source_identity, local)?;
        self.record_import_commit(&source, &import)
    }

    pub fn record_source_receipt(
        &mut self,
        receipt: &SourceReceipt,
    ) -> Result<ReceiptWriteOutcome<SourceReceipt>, MediaStoreError> {
        validate_source_receipt(receipt)?;
        let tx = self.conn.transaction()?;
        let outcome = insert_source_receipt(&tx, receipt)?;
        tx.commit()?;
        Ok(outcome)
    }

    pub fn source_receipt(
        &self,
        source_revision: &str,
    ) -> Result<Option<SourceReceipt>, MediaStoreError> {
        read_source_receipt(&self.conn, source_revision)
    }

    pub fn record_derived_receipt(
        &mut self,
        receipt: &DerivedReceipt,
    ) -> Result<ReceiptWriteOutcome<DerivedReceipt>, MediaStoreError> {
        validate_derived_receipt(receipt)?;
        let tx = self.conn.transaction()?;
        let outcome = insert_derived_receipt(&tx, receipt)?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Adapts the pipeline owner's typed local completion evidence without
    /// inventing manifest or inventory digests that the receipt does not
    /// carry.
    pub fn record_local_derived_receipt(
        &mut self,
        local: &LocalDerivedReceipt,
    ) -> Result<ReceiptWriteOutcome<DerivedReceipt>, MediaStoreError> {
        let receipt = local_derived_receipt_row(local)?;
        self.record_derived_receipt(&receipt)
    }

    pub fn derived_receipt(
        &self,
        derived_revision: &str,
    ) -> Result<Option<DerivedReceipt>, MediaStoreError> {
        read_derived_receipt(&self.conn, derived_revision)
    }

    pub fn latest_derived_receipt(
        &self,
        source_revision: &str,
        profile_revision: &str,
    ) -> Result<Option<DerivedReceipt>, MediaStoreError> {
        let revision: Option<String> = self
            .conn
            .query_row(
                "SELECT derived_revision FROM media_derived_receipts \
                 WHERE source_revision = ?1 AND profile_revision = ?2 \
                 ORDER BY committed_at DESC, derived_revision DESC LIMIT 1",
                rusqlite::params![source_revision, profile_revision],
                |row| row.get(0),
            )
            .optional()?;
        revision
            .map(|revision| read_derived_receipt(&self.conn, &revision))
            .transpose()
            .map(Option::flatten)
    }

    pub fn derived_receipt_for_job(
        &self,
        derivation_job_id: &str,
    ) -> Result<Option<DerivedReceipt>, MediaStoreError> {
        let revision: Option<String> = self
            .conn
            .query_row(
                "SELECT derived_revision FROM media_derived_receipts \
                 WHERE derivation_job_id = ?1",
                [derivation_job_id],
                |row| row.get(0),
            )
            .optional()?;
        revision
            .map(|revision| read_derived_receipt(&self.conn, &revision))
            .transpose()
            .map(Option::flatten)
    }

    /// Records the durable source seal and its long-lived import fence in
    /// one transaction. A crash cannot leave `AlreadyImported` without the
    /// source receipt needed to revalidate its local bytes.
    pub fn record_import_commit(
        &mut self,
        source: &SourceReceipt,
        import: &LibraryImportReceipt,
    ) -> Result<ReceiptWriteOutcome<LibraryImportReceipt>, MediaStoreError> {
        validate_source_receipt(source)?;
        validate_import_receipt(import)?;
        if source.source_revision != import.source_revision
            || source.source_identity != import.source_identity
            || source.sealed_inventory_digest != import.sealed_inventory_digest
            || source.local_path != import.local_path
            || source.provenance != import.provenance
            || source.commit_receipt != import.commit_receipt
        {
            return Err(MediaStoreError::Conflict {
                detail: "source and import receipts describe different local commits".to_string(),
            });
        }

        let tx = self.conn.transaction()?;
        insert_source_receipt(&tx, source)?;
        let outcome = insert_import_receipt(&tx, import)?;
        tx.commit()?;
        Ok(outcome)
    }

    pub fn import_receipt_by_source(
        &self,
        source_identity: &str,
        source_revision: &str,
    ) -> Result<Option<LibraryImportReceipt>, MediaStoreError> {
        let receipt_id: Option<String> = self
            .conn
            .query_row(
                "SELECT receipt_id FROM media_import_receipts \
                 WHERE source_identity = ?1 AND source_revision = ?2",
                rusqlite::params![source_identity, source_revision],
                |row| row.get(0),
            )
            .optional()?;
        receipt_id
            .map(|receipt_id| read_import_receipt(&self.conn, &receipt_id))
            .transpose()
            .map(Option::flatten)
    }

    /// Resolve the import receipt that sealed one source revision.
    ///
    /// A derived receipt names only the source revision it was produced from,
    /// but a library entry is keyed by source identity *and* revision. This
    /// lookup supplies the missing identity from the immutable import receipt
    /// rather than letting a derivation assert which entry it belongs to.
    pub fn import_receipt_by_source_revision(
        &self,
        source_revision: &str,
    ) -> Result<Option<LibraryImportReceipt>, MediaStoreError> {
        let receipt_id: Option<String> = self
            .conn
            .query_row(
                "SELECT receipt_id FROM media_import_receipts WHERE source_revision = ?1 \
                 ORDER BY committed_at ASC, receipt_id ASC LIMIT 1",
                [source_revision],
                |row| row.get(0),
            )
            .optional()?;
        receipt_id
            .map(|receipt_id| read_import_receipt(&self.conn, &receipt_id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn import_receipt_for_job(
        &self,
        import_job_id: &str,
    ) -> Result<Option<LibraryImportReceipt>, MediaStoreError> {
        let receipt_id: Option<String> = self
            .conn
            .query_row(
                "SELECT receipt_id FROM media_import_receipts WHERE import_job_id = ?1",
                [import_job_id],
                |row| row.get(0),
            )
            .optional()?;
        receipt_id
            .map(|receipt_id| read_import_receipt(&self.conn, &receipt_id))
            .transpose()
            .map(Option::flatten)
    }
}

pub(crate) fn local_source_receipt_rows(
    receipt_id: &str,
    import_job_id: &ImportJobId,
    source_identity: &str,
    local: &LocalSourceReceipt,
) -> Result<(SourceReceipt, LibraryImportReceipt), MediaStoreError> {
    let source_revision = local.content_revision().as_str().to_string();
    let inventory_digest = local.inventory_digest().digest_hex().to_string();
    let provenance = serde_json::to_value(local.provenance())?;
    let commit_receipt = serde_json::Value::String(local.commit_receipt().to_string());
    let source = SourceReceipt {
        source_revision: source_revision.clone(),
        source_identity: source_identity.to_string(),
        sealed_inventory_digest: inventory_digest.clone(),
        provenance: provenance.clone(),
        local_path: local.sealed_relative_path().as_str().to_string(),
        commit_receipt: commit_receipt.clone(),
        verified_at: local.committed_at().to_string(),
    };
    let import = LibraryImportReceipt {
        receipt_id: receipt_id.to_string(),
        import_job_id: import_job_id.as_str().to_string(),
        source_revision,
        source_identity: source_identity.to_string(),
        sealed_inventory_digest: inventory_digest,
        provenance,
        local_path: local.sealed_relative_path().as_str().to_string(),
        commit_receipt,
        committed_at: local.committed_at().to_string(),
    };
    Ok((source, import))
}

pub(crate) fn local_derived_receipt_row(
    local: &LocalDerivedReceipt,
) -> Result<DerivedReceipt, MediaStoreError> {
    let receipt = DerivedReceipt {
        derivation_job_id: local.derivation_job_id().as_str().to_string(),
        derived_revision: local.derived_revision().as_str().to_string(),
        source_revision: local.source_revision().as_str().to_string(),
        source_manifest_digest: local.source_manifest_digest().as_str().to_string(),
        profile_revision: local.profile_revision().as_str().to_string(),
        local_path: local.sealed_artifact().as_str().to_string(),
        commit_receipt: serde_json::Value::String(local.commit_receipt().to_string()),
        committed_at: local.committed_at().to_string(),
    };
    validate_derived_receipt(&receipt)?;
    Ok(receipt)
}

pub(crate) fn insert_source_receipt(
    tx: &Transaction<'_>,
    receipt: &SourceReceipt,
) -> Result<ReceiptWriteOutcome<SourceReceipt>, MediaStoreError> {
    if let Some(existing) = read_source_receipt(tx, &receipt.source_revision)? {
        if existing == *receipt {
            return Ok(ReceiptWriteOutcome::Existing(existing));
        }
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "source revision {:?} already has different immutable receipt evidence",
                receipt.source_revision
            ),
        });
    }
    tx.execute(
        "INSERT INTO media_source_receipts (
             source_revision, source_identity, sealed_inventory_digest, provenance_json,
             local_path, commit_receipt_json, verified_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            receipt.source_revision,
            receipt.source_identity,
            receipt.sealed_inventory_digest,
            serde_json::to_string(&receipt.provenance)?,
            receipt.local_path,
            serde_json::to_string(&receipt.commit_receipt)?,
            receipt.verified_at,
        ],
    )?;
    Ok(ReceiptWriteOutcome::Recorded(receipt.clone()))
}

pub(crate) fn insert_derived_receipt(
    tx: &Transaction<'_>,
    receipt: &DerivedReceipt,
) -> Result<ReceiptWriteOutcome<DerivedReceipt>, MediaStoreError> {
    if let Some(existing) = read_derived_receipt(tx, &receipt.derived_revision)? {
        if existing == *receipt {
            return Ok(ReceiptWriteOutcome::Existing(existing));
        }
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "derived revision {:?} already has different immutable receipt evidence",
                receipt.derived_revision
            ),
        });
    }
    tx.execute(
        "INSERT INTO media_derived_receipts (
             derived_revision, derivation_job_id, source_revision, source_manifest_digest,
             profile_revision, local_path, commit_receipt_json, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            receipt.derived_revision,
            receipt.derivation_job_id,
            receipt.source_revision,
            receipt.source_manifest_digest,
            receipt.profile_revision,
            receipt.local_path,
            serde_json::to_string(&receipt.commit_receipt)?,
            receipt.committed_at,
        ],
    )?;
    Ok(ReceiptWriteOutcome::Recorded(receipt.clone()))
}

pub(crate) fn insert_import_receipt(
    tx: &Transaction<'_>,
    receipt: &LibraryImportReceipt,
) -> Result<ReceiptWriteOutcome<LibraryImportReceipt>, MediaStoreError> {
    if let Some(existing) = read_import_receipt(tx, &receipt.receipt_id)? {
        if existing == *receipt {
            return Ok(ReceiptWriteOutcome::Existing(existing));
        }
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "import receipt id {:?} already has different evidence",
                receipt.receipt_id
            ),
        });
    }
    if let Some(existing) =
        read_import_receipt_by_natural_key(tx, &receipt.source_identity, &receipt.source_revision)?
    {
        if existing == *receipt {
            return Ok(ReceiptWriteOutcome::Existing(existing));
        }
        return Err(MediaStoreError::Conflict {
            detail: format!(
                "source identity {:?} revision {:?} already has a different import receipt",
                receipt.source_identity, receipt.source_revision
            ),
        });
    }
    tx.execute(
        "INSERT INTO media_import_receipts (
             receipt_id, import_job_id, source_revision, source_identity,
             sealed_inventory_digest, provenance_json, local_path, commit_receipt_json,
             committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            receipt.receipt_id,
            receipt.import_job_id,
            receipt.source_revision,
            receipt.source_identity,
            receipt.sealed_inventory_digest,
            serde_json::to_string(&receipt.provenance)?,
            receipt.local_path,
            serde_json::to_string(&receipt.commit_receipt)?,
            receipt.committed_at,
        ],
    )?;
    Ok(ReceiptWriteOutcome::Recorded(receipt.clone()))
}

fn read_source_receipt(
    conn: &rusqlite::Connection,
    revision: &str,
) -> Result<Option<SourceReceipt>, MediaStoreError> {
    let raw: Option<SourceReceiptRow> = conn
        .query_row(
            "SELECT source_revision, source_identity, sealed_inventory_digest,
                    provenance_json, local_path, commit_receipt_json, verified_at
             FROM media_source_receipts WHERE source_revision = ?1",
            [revision],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    raw.map(decode_source_receipt).transpose()
}

fn decode_source_receipt(raw: SourceReceiptRow) -> Result<SourceReceipt, MediaStoreError> {
    Ok(SourceReceipt {
        source_revision: raw.0,
        source_identity: raw.1,
        sealed_inventory_digest: raw.2,
        provenance: serde_json::from_str(&raw.3).map_err(|error| {
            MediaStoreError::corrupt("media_source_receipts", error.to_string())
        })?,
        local_path: raw.4,
        commit_receipt: serde_json::from_str(&raw.5).map_err(|error| {
            MediaStoreError::corrupt("media_source_receipts", error.to_string())
        })?,
        verified_at: raw.6,
    })
}

pub(crate) fn read_derived_receipt(
    conn: &rusqlite::Connection,
    revision: &str,
) -> Result<Option<DerivedReceipt>, MediaStoreError> {
    let raw: Option<DerivedReceiptRow> = conn
        .query_row(
            "SELECT derived_revision, derivation_job_id, source_revision,
                    source_manifest_digest, profile_revision, local_path,
                    commit_receipt_json, committed_at
             FROM media_derived_receipts WHERE derived_revision = ?1",
            [revision],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let receipt = DerivedReceipt {
            derived_revision: raw.0,
            derivation_job_id: raw.1,
            source_revision: raw.2,
            source_manifest_digest: raw.3,
            profile_revision: raw.4,
            local_path: raw.5,
            commit_receipt: serde_json::from_str(&raw.6).map_err(|error| {
                MediaStoreError::corrupt("media_derived_receipts", error.to_string())
            })?,
            committed_at: raw.7,
        };
        validate_derived_receipt(&receipt)?;
        Ok(receipt)
    })
    .transpose()
}

fn read_import_receipt(
    conn: &rusqlite::Connection,
    receipt_id: &str,
) -> Result<Option<LibraryImportReceipt>, MediaStoreError> {
    read_import_receipt_where(conn, "receipt_id", receipt_id, None)
}

fn read_import_receipt_by_natural_key(
    conn: &rusqlite::Connection,
    source_identity: &str,
    source_revision: &str,
) -> Result<Option<LibraryImportReceipt>, MediaStoreError> {
    read_import_receipt_where(
        conn,
        "source_identity",
        source_identity,
        Some(source_revision),
    )
}

fn read_import_receipt_where(
    conn: &rusqlite::Connection,
    field: &str,
    value: &str,
    source_revision: Option<&str>,
) -> Result<Option<LibraryImportReceipt>, MediaStoreError> {
    let sql = if source_revision.is_some() {
        "SELECT receipt_id, import_job_id, source_revision, source_identity,
                sealed_inventory_digest, provenance_json, local_path, commit_receipt_json,
                committed_at
         FROM media_import_receipts WHERE source_identity = ?1 AND source_revision = ?2"
    } else {
        debug_assert_eq!(field, "receipt_id");
        "SELECT receipt_id, import_job_id, source_revision, source_identity,
                sealed_inventory_digest, provenance_json, local_path, commit_receipt_json,
                committed_at
         FROM media_import_receipts WHERE receipt_id = ?1"
    };
    let map = |row: &rusqlite::Row<'_>| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
        ))
    };
    let raw = match source_revision {
        Some(revision) => conn
            .query_row(sql, rusqlite::params![value, revision], map)
            .optional()?,
        None => conn.query_row(sql, [value], map).optional()?,
    };
    raw.map(|raw| {
        Ok(LibraryImportReceipt {
            receipt_id: raw.0,
            import_job_id: raw.1,
            source_revision: raw.2,
            source_identity: raw.3,
            sealed_inventory_digest: raw.4,
            provenance: serde_json::from_str(&raw.5).map_err(|error| {
                MediaStoreError::corrupt("media_import_receipts", error.to_string())
            })?,
            local_path: raw.6,
            commit_receipt: serde_json::from_str(&raw.7).map_err(|error| {
                MediaStoreError::corrupt("media_import_receipts", error.to_string())
            })?,
            committed_at: raw.8,
        })
    })
    .transpose()
}

fn validate_source_receipt(receipt: &SourceReceipt) -> Result<(), MediaStoreError> {
    require_non_empty(&receipt.source_revision, "source_revision")?;
    require_non_empty(&receipt.source_identity, "source_identity")?;
    require_sha256(&receipt.sealed_inventory_digest, "sealed_inventory_digest")?;
    require_non_empty(&receipt.local_path, "local_path")?;
    require_non_empty(&receipt.verified_at, "verified_at")
}

fn validate_derived_receipt(receipt: &DerivedReceipt) -> Result<(), MediaStoreError> {
    require_non_empty(&receipt.derivation_job_id, "derivation_job_id")?;
    require_sha256_identity(&receipt.derived_revision, "derived_revision")?;
    require_sha256_identity(&receipt.source_revision, "source_revision")?;
    require_sha256_identity(&receipt.source_manifest_digest, "source_manifest_digest")?;
    require_sha256_identity(&receipt.profile_revision, "profile_revision")?;
    require_non_empty(&receipt.local_path, "local_path")?;
    require_non_empty(&receipt.committed_at, "committed_at")?;
    let Some(commit_receipt) = receipt.commit_receipt.as_str() else {
        return Err(MediaStoreError::Conflict {
            detail: "derived commit_receipt must be a JSON string".to_string(),
        });
    };
    require_non_empty(commit_receipt, "commit_receipt")
}

fn require_sha256_identity(value: &str, field: &str) -> Result<(), MediaStoreError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| MediaStoreError::Conflict {
            detail: format!("{field} must use the sha256:<digest> identity form"),
        })?;
    require_sha256(digest, field)
}

fn validate_import_receipt(receipt: &LibraryImportReceipt) -> Result<(), MediaStoreError> {
    require_non_empty(&receipt.receipt_id, "receipt_id")?;
    require_non_empty(&receipt.import_job_id, "import_job_id")?;
    require_non_empty(&receipt.source_revision, "source_revision")?;
    require_non_empty(&receipt.source_identity, "source_identity")?;
    require_sha256(&receipt.sealed_inventory_digest, "sealed_inventory_digest")?;
    require_non_empty(&receipt.local_path, "local_path")?;
    require_non_empty(&receipt.committed_at, "committed_at")
}
