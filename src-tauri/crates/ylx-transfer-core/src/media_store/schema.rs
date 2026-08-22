//! Forward-only, namespaced schema for removable-media import and normalization.
//!
//! These tables may live in the same SQLite file as `TransferStore`, but use
//! their own migration history and identity. Neither store can advance or
//! reinterpret the other store's schema high-water mark.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::error::MediaStoreError;

pub const MEDIA_STORE_IDENTITY: &str = "ylx-transfer/media-store";
pub const CURRENT_IMPORT_SPEC_VERSION: u32 = 1;
pub const CURRENT_DERIVATION_SPEC_VERSION: u32 = 1;

const MIGRATION_TABLE: &str = "media_schema_migrations";

/// Immutable, append-only migration history. Never edit SQL at a released
/// version; add a new version instead. Checksums make accidental drift fail
/// closed before any new migration runs.
pub const MIGRATIONS: &[(u32, &str)] = &[
    (
        1,
        r#"
        CREATE TABLE media_generations (
            generation_id       TEXT PRIMARY KEY CHECK (length(generation_id) > 0),
            identity_digest     TEXT NOT NULL CHECK (length(identity_digest) = 64),
            generation_json     TEXT NOT NULL CHECK (json_valid(generation_json)),
            observation_epoch   INTEGER NOT NULL CHECK (observation_epoch >= 0),
            is_present          INTEGER NOT NULL CHECK (is_present IN (0, 1)),
            first_observed_at   TEXT NOT NULL,
            last_observed_at    TEXT NOT NULL
        );
        CREATE INDEX media_generations_identity_idx
            ON media_generations (identity_digest, observation_epoch);

        CREATE TABLE media_import_jobs (
            job_id              TEXT PRIMARY KEY CHECK (length(job_id) > 0),
            natural_key         TEXT NOT NULL UNIQUE CHECK (length(natural_key) > 0),
            request_digest      TEXT NOT NULL CHECK (
                length(request_digest) = 64 OR
                (length(request_digest) = 71 AND substr(request_digest, 1, 7) = 'sha256:')
            ),
            snapshot_json       TEXT NOT NULL CHECK (json_valid(snapshot_json)),
            state_version       INTEGER NOT NULL CHECK (state_version >= 0),
            is_terminal         INTEGER NOT NULL CHECK (is_terminal IN (0, 1)),
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        );

        CREATE TABLE media_import_specs (
            job_id              TEXT PRIMARY KEY
                                REFERENCES media_import_jobs(job_id) ON DELETE CASCADE,
            spec_version        INTEGER NOT NULL CHECK (spec_version > 0),
            spec_json           TEXT NOT NULL CHECK (json_valid(spec_json))
        );

        CREATE TABLE media_import_files (
            job_id              TEXT NOT NULL
                                REFERENCES media_import_jobs(job_id) ON DELETE CASCADE,
            ordinal             INTEGER NOT NULL CHECK (ordinal >= 0),
            file_id             TEXT NOT NULL CHECK (length(file_id) > 0),
            expected_size       INTEGER NOT NULL CHECK (expected_size >= 0),
            expected_sha256     TEXT CHECK (expected_sha256 IS NULL OR length(expected_sha256) = 64),
            file_spec_json      TEXT NOT NULL CHECK (json_valid(file_spec_json)),
            PRIMARY KEY (job_id, file_id),
            UNIQUE (job_id, ordinal)
        );

        CREATE TABLE media_import_checkpoints (
            job_id              TEXT NOT NULL,
            file_id             TEXT NOT NULL,
            durable_offset      INTEGER NOT NULL CHECK (durable_offset >= 0),
            expected_size       INTEGER NOT NULL CHECK (expected_size >= 0),
            source_sha256       TEXT CHECK (source_sha256 IS NULL OR length(source_sha256) = 64),
            target_sha256       TEXT CHECK (target_sha256 IS NULL OR length(target_sha256) = 64),
            verified            INTEGER NOT NULL CHECK (verified IN (0, 1)),
            checkpoint_json     TEXT NOT NULL CHECK (json_valid(checkpoint_json)),
            updated_at          TEXT NOT NULL,
            PRIMARY KEY (job_id, file_id),
            FOREIGN KEY (job_id, file_id)
                REFERENCES media_import_files(job_id, file_id) ON DELETE CASCADE,
            CHECK (durable_offset <= expected_size),
            CHECK (verified = 0 OR (
                durable_offset = expected_size
                AND source_sha256 IS NOT NULL
                AND target_sha256 IS NOT NULL
            ))
        );

        CREATE TABLE media_import_locators (
            job_id              TEXT PRIMARY KEY
                                REFERENCES media_import_jobs(job_id) ON DELETE CASCADE,
            media_generation_id TEXT
                                REFERENCES media_generations(generation_id),
            locator_version     INTEGER NOT NULL CHECK (locator_version >= 1),
            locator_json        TEXT NOT NULL CHECK (json_valid(locator_json)),
            installed_at        TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        );

        CREATE TABLE media_import_outbox (
            sequence            INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id              TEXT NOT NULL UNIQUE
                                REFERENCES media_import_jobs(job_id) ON DELETE CASCADE,
            outcome_json        TEXT NOT NULL CHECK (json_valid(outcome_json)),
            state_version       INTEGER NOT NULL CHECK (state_version >= 0),
            recorded_at         TEXT NOT NULL,
            acknowledged_at     TEXT
        );
        CREATE INDEX media_import_outbox_pending_idx
            ON media_import_outbox (acknowledged_at, sequence);
        "#,
    ),
    (
        2,
        r#"
        CREATE TABLE media_derivation_jobs (
            job_id              TEXT PRIMARY KEY CHECK (length(job_id) > 0),
            natural_key         TEXT NOT NULL UNIQUE CHECK (length(natural_key) > 0),
            request_digest      TEXT NOT NULL CHECK (
                length(request_digest) = 64 OR
                (length(request_digest) = 71 AND substr(request_digest, 1, 7) = 'sha256:')
            ),
            snapshot_json       TEXT NOT NULL CHECK (json_valid(snapshot_json)),
            state_version       INTEGER NOT NULL CHECK (state_version >= 0),
            is_terminal         INTEGER NOT NULL CHECK (is_terminal IN (0, 1)),
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        );

        CREATE TABLE media_derivation_specs (
            job_id              TEXT PRIMARY KEY
                                REFERENCES media_derivation_jobs(job_id) ON DELETE CASCADE,
            source_revision     TEXT NOT NULL CHECK (length(source_revision) > 0),
            profile_revision    TEXT NOT NULL CHECK (length(profile_revision) > 0),
            spec_version        INTEGER NOT NULL CHECK (spec_version > 0),
            spec_json           TEXT NOT NULL CHECK (json_valid(spec_json))
        );
        CREATE INDEX media_derivation_jobs_source_profile_idx
            ON media_derivation_specs (source_revision, profile_revision);

        -- A left/right segment pair is the indivisible recovery unit.
        CREATE TABLE media_derivation_segment_pairs (
            job_id              TEXT NOT NULL
                                REFERENCES media_derivation_jobs(job_id) ON DELETE CASCADE,
            segment_index       INTEGER NOT NULL CHECK (segment_index >= 0),
            pair_state          TEXT NOT NULL CHECK (length(pair_state) > 0),
            pair_version        INTEGER NOT NULL CHECK (pair_version >= 0),
            segment_json        TEXT NOT NULL CHECK (json_valid(segment_json)),
            left_sha256         TEXT CHECK (left_sha256 IS NULL OR length(left_sha256) = 64),
            right_sha256        TEXT CHECK (right_sha256 IS NULL OR length(right_sha256) = 64),
            verified            INTEGER NOT NULL CHECK (verified IN (0, 1)),
            updated_at          TEXT NOT NULL,
            PRIMARY KEY (job_id, segment_index),
            CHECK (verified = 0 OR (left_sha256 IS NOT NULL AND right_sha256 IS NOT NULL))
        );

        CREATE TABLE media_derivation_outbox (
            sequence            INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id              TEXT NOT NULL UNIQUE
                                REFERENCES media_derivation_jobs(job_id) ON DELETE CASCADE,
            outcome_json        TEXT NOT NULL CHECK (json_valid(outcome_json)),
            state_version       INTEGER NOT NULL CHECK (state_version >= 0),
            recorded_at         TEXT NOT NULL,
            acknowledged_at     TEXT
        );
        CREATE INDEX media_derivation_outbox_pending_idx
            ON media_derivation_outbox (acknowledged_at, sequence);
        "#,
    ),
    (
        3,
        r#"
        CREATE TABLE media_pipelines (
            pipeline_id         TEXT PRIMARY KEY CHECK (length(pipeline_id) > 0),
            source_key          TEXT NOT NULL UNIQUE CHECK (length(source_key) > 0),
            pipeline_json       TEXT NOT NULL CHECK (json_valid(pipeline_json)),
            policy_json         TEXT NOT NULL CHECK (json_valid(policy_json)),
            action_required_json TEXT CHECK (
                action_required_json IS NULL OR json_valid(action_required_json)
            ),
            pipeline_version    INTEGER NOT NULL CHECK (pipeline_version >= 1),
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        );

        CREATE TABLE media_pipeline_dependencies (
            pipeline_id         TEXT NOT NULL
                                REFERENCES media_pipelines(pipeline_id) ON DELETE CASCADE,
            ordinal             INTEGER NOT NULL CHECK (ordinal >= 0),
            stage               TEXT NOT NULL CHECK (stage IN ('import', 'derivation', 'upload')),
            job_id              TEXT NOT NULL CHECK (length(job_id) > 0),
            required_milestone  TEXT NOT NULL CHECK (length(required_milestone) > 0),
            dependency_json     TEXT NOT NULL CHECK (json_valid(dependency_json)),
            PRIMARY KEY (pipeline_id, stage),
            UNIQUE (pipeline_id, ordinal)
        );
        "#,
    ),
    (
        4,
        r#"
        CREATE TABLE media_source_receipts (
            source_revision     TEXT PRIMARY KEY CHECK (length(source_revision) > 0),
            source_identity     TEXT NOT NULL CHECK (length(source_identity) > 0),
            sealed_inventory_digest TEXT NOT NULL CHECK (length(sealed_inventory_digest) = 64),
            provenance_json     TEXT NOT NULL CHECK (json_valid(provenance_json)),
            local_path          TEXT NOT NULL CHECK (length(local_path) > 0),
            commit_receipt_json TEXT NOT NULL CHECK (json_valid(commit_receipt_json)),
            verified_at         TEXT NOT NULL
        );

        CREATE TABLE media_derived_receipts (
            derived_revision    TEXT PRIMARY KEY CHECK (length(derived_revision) > 0),
            derivation_job_id   TEXT NOT NULL UNIQUE
                                REFERENCES media_derivation_jobs(job_id),
            source_revision     TEXT NOT NULL CHECK (length(source_revision) > 0),
            source_manifest_digest TEXT NOT NULL CHECK (length(source_manifest_digest) > 0),
            profile_revision    TEXT NOT NULL CHECK (length(profile_revision) > 0),
            local_path          TEXT NOT NULL CHECK (length(local_path) > 0),
            commit_receipt_json TEXT NOT NULL CHECK (json_valid(commit_receipt_json)),
            committed_at        TEXT NOT NULL
        );
        CREATE INDEX media_derived_receipts_source_profile_idx
            ON media_derived_receipts (source_revision, profile_revision, committed_at);

        CREATE TABLE media_import_receipts (
            receipt_id          TEXT PRIMARY KEY CHECK (length(receipt_id) > 0),
            import_job_id       TEXT NOT NULL UNIQUE
                                REFERENCES media_import_jobs(job_id),
            source_revision     TEXT NOT NULL
                                REFERENCES media_source_receipts(source_revision),
            source_identity     TEXT NOT NULL CHECK (length(source_identity) > 0),
            sealed_inventory_digest TEXT NOT NULL CHECK (length(sealed_inventory_digest) = 64),
            provenance_json     TEXT NOT NULL CHECK (json_valid(provenance_json)),
            local_path          TEXT NOT NULL CHECK (length(local_path) > 0),
            commit_receipt_json TEXT NOT NULL CHECK (json_valid(commit_receipt_json)),
            committed_at        TEXT NOT NULL,
            UNIQUE (source_identity, source_revision)
        );
        "#,
    ),
    (
        5,
        r#"
        CREATE TABLE media_library_lease_epochs (
            revision_kind       TEXT NOT NULL CHECK (revision_kind IN ('source', 'derived')),
            revision_id         TEXT NOT NULL CHECK (length(revision_id) > 0),
            last_fencing_token  INTEGER NOT NULL CHECK (last_fencing_token >= 0),
            PRIMARY KEY (revision_kind, revision_id)
        );

        CREATE TABLE media_library_revision_leases (
            lease_id            TEXT PRIMARY KEY CHECK (length(lease_id) > 0),
            revision_kind       TEXT NOT NULL CHECK (revision_kind IN ('source', 'derived')),
            revision_id         TEXT NOT NULL CHECK (length(revision_id) > 0),
            owner_id            TEXT NOT NULL CHECK (length(owner_id) > 0),
            lease_mode          TEXT NOT NULL CHECK (lease_mode IN ('shared', 'exclusive')),
            fencing_token       INTEGER NOT NULL CHECK (fencing_token >= 1),
            acquired_at         TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            expires_at_ms       INTEGER NOT NULL CHECK (expires_at_ms >= 0),
            UNIQUE (revision_kind, revision_id, fencing_token),
            FOREIGN KEY (revision_kind, revision_id)
                REFERENCES media_library_lease_epochs(revision_kind, revision_id)
        );
        CREATE INDEX media_library_revision_leases_active_idx
            ON media_library_revision_leases (
                revision_kind, revision_id, expires_at_ms, lease_mode
            );
        "#,
    ),
    (
        6,
        r#"
        -- Collection revisions are owner commit sequences, not max job
        -- versions. Adding a version-0/1 job after an old version-10 job
        -- must still advance the collection observed by stale-drop clients.
        CREATE TABLE media_projection_revisions (
            resource            TEXT PRIMARY KEY CHECK (
                resource IN ('imports', 'derivations', 'pipelines')
            ),
            revision            INTEGER NOT NULL CHECK (revision >= 0)
        );
        INSERT INTO media_projection_revisions (resource, revision) VALUES
            ('imports', 0),
            ('derivations', 0),
            ('pipelines', 0);
        "#,
    ),
    (
        7,
        r#"
        -- PC-owned trusted producer keys. Trust originates from a SAS
        -- transcript the operator confirmed on this machine, never from a
        -- key or fingerprint carried on removable media. The registry
        -- therefore keeps the confirmed fingerprint plus a digest of the
        -- pairing evidence, and never stores a connection token or secret.
        CREATE TABLE media_trusted_producer_keys (
            producer_identity        TEXT NOT NULL CHECK (length(producer_identity) > 0),
            key_fingerprint          TEXT NOT NULL CHECK (
                length(key_fingerprint) = 71 AND substr(key_fingerprint, 1, 7) = 'sha256:'
            ),
            trust_source             TEXT NOT NULL CHECK (trust_source = 'sas_pairing'),
            pairing_evidence_digest  TEXT NOT NULL CHECK (length(pairing_evidence_digest) = 64),
            confirmed_at             TEXT NOT NULL CHECK (length(confirmed_at) > 0),
            revoked_at               TEXT,
            PRIMARY KEY (producer_identity, key_fingerprint)
        );

        CREATE UNIQUE INDEX media_trusted_producer_active_identity
            ON media_trusted_producer_keys (producer_identity)
            WHERE revoked_at IS NULL;

        CREATE UNIQUE INDEX media_trusted_producer_active_fingerprint
            ON media_trusted_producer_keys (key_fingerprint)
            WHERE revoked_at IS NULL;

        -- Explicit, append-only audit of every trust mutation. Removing a
        -- device from the UI is not a revocation; a revocation is its own
        -- recorded action.
        CREATE TABLE media_trusted_producer_audit (
            sequence                 INTEGER PRIMARY KEY AUTOINCREMENT,
            producer_identity        TEXT NOT NULL CHECK (length(producer_identity) > 0),
            key_fingerprint          TEXT NOT NULL CHECK (length(key_fingerprint) > 0),
            action                   TEXT NOT NULL CHECK (
                action IN ('confirmed', 'rotated', 'revoked')
            ),
            pairing_evidence_digest  TEXT NOT NULL CHECK (length(pairing_evidence_digest) = 64),
            recorded_at              TEXT NOT NULL
        );
        CREATE INDEX media_trusted_producer_audit_identity_idx
            ON media_trusted_producer_audit (producer_identity, sequence);
        "#,
    ),
    (
        8,
        r#"
        CREATE TABLE media_trusted_inline_publication_keys (
            producer_identity TEXT NOT NULL,
            key_version INTEGER NOT NULL CHECK (key_version > 0),
            key_fingerprint TEXT NOT NULL CHECK (length(key_fingerprint) = 71 AND substr(key_fingerprint,1,7)='sha256:'),
            public_key_hex TEXT NOT NULL CHECK (length(public_key_hex)=64),
            not_before TEXT NOT NULL,
            not_after TEXT,
            revoked_at TEXT,
            registry_revision INTEGER NOT NULL CHECK (registry_revision >= 0),
            PRIMARY KEY (producer_identity, key_version)
        );
        "#,
    ),
];

#[must_use]
pub fn latest_version() -> u32 {
    MIGRATIONS.last().map_or(0, |(version, _)| *version)
}

pub(crate) fn read_schema_version(conn: &Connection) -> Result<u32, MediaStoreError> {
    if !table_exists(conn, MIGRATION_TABLE)? {
        return Ok(0);
    }
    let raw: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM media_schema_migrations",
        [],
        |row| row.get(0),
    )?;
    u32::try_from(raw).map_err(|_| {
        MediaStoreError::corrupt(
            MIGRATION_TABLE,
            format!("migration version {raw} is negative or exceeds u32"),
        )
    })
}

pub(crate) fn run_migrations(conn: &mut Connection, path: &Path) -> Result<(), MediaStoreError> {
    validate_manifest()?;

    // Reject a newer file before creating or changing any media-store table.
    let supported = latest_version();
    let current_before_bootstrap = read_schema_version(conn)?;
    if current_before_bootstrap > supported {
        return Err(MediaStoreError::UnsupportedSchemaVersion {
            path: path.to_path_buf(),
            found: current_before_bootstrap,
            supported,
        });
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS media_schema_migrations (
             version    INTEGER PRIMARY KEY CHECK (version > 0),
             checksum   TEXT NOT NULL CHECK (length(checksum) = 64),
             applied_at TEXT NOT NULL DEFAULT (datetime('now'))
         );
         CREATE TABLE IF NOT EXISTS media_store_meta (
             key        TEXT PRIMARY KEY,
             value      TEXT NOT NULL
         );",
    )?;

    let persisted_identity: Option<String> = conn
        .query_row(
            "SELECT value FROM media_store_meta WHERE key = 'identity'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match persisted_identity {
        Some(found) if found != MEDIA_STORE_IDENTITY => {
            return Err(MediaStoreError::corrupt(
                path,
                format!("store identity {found:?} does not match {MEDIA_STORE_IDENTITY:?}"),
            ));
        }
        Some(_) => {}
        None => {
            conn.execute(
                "INSERT INTO media_store_meta (key, value) VALUES ('identity', ?1)",
                [MEDIA_STORE_IDENTITY],
            )?;
        }
    }

    let rows = persisted_migrations(conn)?;
    let current = rows.last().map_or(0, |(version, _)| *version);
    for expected in 1..=current {
        if !rows.iter().any(|(version, _)| *version == expected) {
            return Err(MediaStoreError::Migration {
                version: expected,
                detail: "migration history is missing a prior version".to_string(),
            });
        }
    }
    for (version, actual_checksum) in &rows {
        let Some((_, sql)) = MIGRATIONS
            .iter()
            .find(|(candidate, _)| candidate == version)
        else {
            return Err(MediaStoreError::UnsupportedSchemaVersion {
                path: path.to_path_buf(),
                found: *version,
                supported,
            });
        };
        if actual_checksum != &migration_checksum(sql) {
            return Err(MediaStoreError::corrupt(
                path,
                format!("migration {version} checksum mismatch"),
            ));
        }
    }

    for (version, sql) in MIGRATIONS {
        if *version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .map_err(|error| MediaStoreError::Migration {
                version: *version,
                detail: error.to_string(),
            })?;
        tx.execute(
            "INSERT INTO media_schema_migrations (version, checksum) VALUES (?1, ?2)",
            rusqlite::params![i64::from(*version), migration_checksum(sql)],
        )
        .map_err(|error| MediaStoreError::Migration {
            version: *version,
            detail: error.to_string(),
        })?;
        tx.commit()?;
    }
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, MediaStoreError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .map_err(Into::into)
}

fn persisted_migrations(conn: &Connection) -> Result<Vec<(u32, String)>, MediaStoreError> {
    let mut statement =
        conn.prepare("SELECT version, checksum FROM media_schema_migrations ORDER BY version ASC")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(raw, checksum)| {
            u32::try_from(raw)
                .map(|version| (version, checksum))
                .map_err(|_| {
                    MediaStoreError::corrupt(
                        MIGRATION_TABLE,
                        format!("migration version {raw} is negative or exceeds u32"),
                    )
                })
        })
        .collect()
}

fn validate_manifest() -> Result<(), MediaStoreError> {
    let mut expected = 1u32;
    for (version, _) in MIGRATIONS {
        if *version != expected {
            return Err(MediaStoreError::Migration {
                version: expected,
                detail: format!("migration manifest is not contiguous: found version {version}"),
            });
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| MediaStoreError::Migration {
                version: *version,
                detail: "migration manifest version overflow".to_string(),
            })?;
    }
    Ok(())
}

fn migration_checksum(sql: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(sql.as_bytes());
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_manifest_is_contiguous() {
        validate_manifest().expect("migration manifest");
        assert_eq!(latest_version(), 8);
    }

    #[test]
    fn checksum_is_stable_sha256_hex() {
        let checksum = migration_checksum("SELECT 1;");
        assert_eq!(checksum.len(), 64);
        assert_eq!(checksum, migration_checksum("SELECT 1;"));
        assert_ne!(checksum, migration_checksum("SELECT 2;"));
    }
}
