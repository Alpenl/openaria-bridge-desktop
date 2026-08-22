//! Commit 26: the on-disk shape of the legacy pending-download JSON
//! sidecar, and its conversion into a [`JobSpec`].
//!
//! These structs mirror `src-tauri/src/composition.rs`'s
//! `PendingDownloadStore` / `PersistedPendingDownload` / `PendingDownloadInfo`
//! (and `models.rs`'s `SessionFile` / `PublicationEvidence`) field for
//! field, including their `camelCase` wire names and the `flatten` that
//! makes a persisted record one flat JSON object. They are **read-only**:
//! the importer never writes this format back, and it never rewrites the
//! file it read, so a record that fails conversion leaves the original
//! bytes intact for a retry.
//!
//! Deserialization is deliberately kept separate from validation. Serde
//! only shapes the bytes; every domain rule (non-empty ids, 64-hex
//! digests, requested files that actually appear in the signed inventory)
//! is enforced by [`JobSpec::new`] and [`to_job_spec`], so the importer
//! cannot create a job the live enqueue path would have rejected.

use serde::Deserialize;

use crate::domain::{
    DeviceId, FileId, JobFileSpec, JobIdentity, JobSpec, PublicationMaterial, SessionId,
};

use super::upload_store::{NewUpload, UploadUrlStyle};

/// The only sidecar version this importer understands. Matches
/// `composition.rs`'s `PENDING_DOWNLOAD_STORE_VERSION`.
pub(crate) const LEGACY_STORE_VERSION: u32 = 2;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyPendingDownloadStore {
    pub version: u32,
    #[serde(default)]
    pub downloads: Vec<LegacyPendingDownload>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyPendingDownload {
    pub job_id: String,
    pub device_id: String,
    pub session_id: String,
    #[serde(default)]
    pub date_label: String,
    pub files: Vec<LegacySessionFile>,
    pub session_files: Vec<LegacySessionFile>,
    pub publication: LegacyPublicationEvidence,
    #[serde(default = "default_full_session")]
    pub full_session: bool,
}

fn default_full_session() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacySessionFile {
    #[serde(default, alias = "path")]
    pub file_id: String,
    #[serde(default)]
    pub display_path: String,
    pub bytes: u64,
    #[serde(default)]
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyPublicationEvidence {
    pub revision: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

// ---------------------------------------------------------------------
// Commit 35: the legacy pending-*upload* sidecar
// ---------------------------------------------------------------------

/// The only pending-upload sidecar version this importer understands.
/// Matches the retired `composition.rs` `PENDING_UPLOAD_STORE_VERSION`.
pub(crate) const LEGACY_UPLOAD_STORE_VERSION: u32 = 1;

/// Mirrors the retired `composition.rs` `PendingUploadStore` /
/// `PendingUploadInfo` field for field, including their `camelCase` wire
/// names. Read-only, like the download shapes above: the importer never
/// writes this format back and never rewrites the file it read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyPendingUploadStore {
    pub version: u32,
    #[serde(default)]
    pub uploads: Vec<LegacyPendingUpload>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LegacyPendingUpload {
    pub transfer_key: String,
    #[serde(default)]
    pub entry_key: String,
    pub object_key: String,
    pub upload_id: String,
    #[serde(default)]
    pub endpoint: String,
    pub bucket: String,
}

pub(crate) fn check_upload_store_version(store: &LegacyPendingUploadStore) -> Result<(), String> {
    if store.version != LEGACY_UPLOAD_STORE_VERSION {
        return Err(format!(
            "unsupported pending-upload store version {} (this build imports version {})",
            store.version, LEGACY_UPLOAD_STORE_VERSION
        ));
    }
    Ok(())
}

/// Converts one legacy record into the durable row shape, or explains what
/// is wrong with it.
///
/// The legacy sidecar had no column for the publication revision, so the
/// imported record carries an empty one — documented as "unknown", and
/// harmless because every imported record is stored as `aborting`, which
/// needs only the multipart handle.
pub(crate) fn to_new_upload(record: &LegacyPendingUpload) -> Result<NewUpload, String> {
    let object_key = record.object_key.trim();
    let upload_id = record.upload_id.trim();
    let transfer_key = record.transfer_key.trim();
    let bucket = record.bucket.trim();
    for (label, value) in [
        ("object key", object_key),
        ("upload id", upload_id),
        ("transfer key", transfer_key),
        ("bucket", bucket),
    ] {
        if value.is_empty() {
            return Err(format!("record has an empty {label}"));
        }
    }
    Ok(NewUpload {
        transfer_key: transfer_key.to_string(),
        entry_key: record.entry_key.trim().to_string(),
        revision: String::new(),
        object_key: object_key.to_string(),
        upload_id: upload_id.to_string(),
        endpoint: record.endpoint.trim().to_string(),
        bucket: bucket.to_string(),
        // The legacy sidecar did not record the addressing style. Preserve
        // that uncertainty explicitly; recovery resolves this marker with
        // the current configured style, while every new row records its
        // exact addressing mode.
        url_style: UploadUrlStyle::LegacyConfigured,
    })
}

pub(crate) fn check_store_version(store: &LegacyPendingDownloadStore) -> Result<(), String> {
    if store.version != LEGACY_STORE_VERSION {
        return Err(format!(
            "unsupported pending-download store version {} (this build imports version {})",
            store.version, LEGACY_STORE_VERSION
        ));
    }
    Ok(())
}

/// Converts one legacy record into a complete [`JobSpec`], or explains
/// precisely what is wrong with it.
///
/// The legacy format stores the requested plan and the session inventory
/// as two independent lists, which is exactly the piecemeal shape commit
/// 21 removed. This function collapses them: the inventory becomes the
/// spec's signed file set, the plan becomes a *selection* out of it, and a
/// plan entry whose size/digest disagrees with the inventory entry is
/// rejected rather than silently preferred.
pub(crate) fn to_job_spec(record: &LegacyPendingDownload) -> Result<JobSpec, String> {
    let identity = JobIdentity::new(
        DeviceId(record.device_id.trim().to_string()),
        SessionId(record.session_id.trim().to_string()),
        record.publication.revision.trim(),
    )
    .map_err(|error| format!("unusable job identity: {error}"))?;

    let publication = PublicationMaterial::new(
        record.publication.revision.trim(),
        record.publication.payload.clone(),
        record.publication.signature.clone(),
        record.publication.public_key.clone(),
    )
    .map_err(|error| format!("unusable publication material: {error}"))?;

    let mut session_files = Vec::with_capacity(record.session_files.len());
    for file in &record.session_files {
        session_files.push(to_file_spec(file)?);
    }

    let mut requested_ids = Vec::with_capacity(record.files.len());
    for file in &record.files {
        let requested = to_file_spec(file)?;
        let Some(inventory) = session_files
            .iter()
            .find(|candidate| candidate.file_id() == requested.file_id())
        else {
            return Err(format!(
                "requested file {:?} is not part of the session inventory",
                requested.file_id().as_str()
            ));
        };
        if inventory != &requested {
            return Err(format!(
                "requested file {:?} disagrees with the session inventory (inventory size {} sha \
                 {}, request size {} sha {})",
                requested.file_id().as_str(),
                inventory.size_bytes(),
                inventory.sha256(),
                requested.size_bytes(),
                requested.sha256(),
            ));
        }
        requested_ids.push(requested.file_id().clone());
    }

    JobSpec::new(
        identity,
        publication,
        session_files,
        &requested_ids,
        record.full_session,
        record.date_label.clone(),
    )
    .map_err(|error| format!("record does not form a valid job spec: {error}"))
}

fn to_file_spec(file: &LegacySessionFile) -> Result<JobFileSpec, String> {
    let file_id = file.file_id.trim();
    // Legacy entries written before `display_path` existed fall back to the
    // opaque file id, exactly as `models::SessionFile::new` does.
    let display_path = if file.display_path.trim().is_empty() {
        file_id
    } else {
        file.display_path.trim()
    };
    JobFileSpec::new(
        FileId(file_id.to_string()),
        display_path,
        file.bytes,
        file.sha256.trim().to_ascii_lowercase(),
    )
    .map_err(|error| format!("file {file_id:?} is unusable: {error}"))
}
