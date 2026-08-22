//! SQLite schema and migrations for the durable transfer store.
//!
//! The forward-only schema records library entries, file inventories, jobs,
//! checkpoints, and object-store receipts used by the production transfer
//! coordinator. Device, session, and file IDs remain opaque `TEXT` values at
//! this persistence boundary. Storage-profile settings stay in the existing
//! `storage_config` table rather than being duplicated here.
//!
//! ## No secrets in this schema
//!
//! None of the tables below have a column for a raw token, password, or S3
//! secret key. `checkpoints.expected_etag` and `receipts.evidence` store
//! *server-observed, non-secret* identifiers (an HTTP ETag, an S3 version
//! ID, a HEAD-response digest) — proof that a transfer happened, never a
//! credential that could authenticate a new request. Raw credentials stay
//! in the credential vault; only opaque non-secret references belong here. See
//! `journal_spike::schema_has_no_secret_columns` for the machine-checked
//! version of this claim.

/// Ordered, forward-only migrations for the transfer database. Versions
/// 1-5 are retained as compatibility DDL for files created by the retired
/// journal implementation; current runtime reads and writes use the
/// `transfer_*` tables added by version 6 and later. Each entry is applied at
/// most once, tracked in `schema_migrations`, inside its own transaction.
///
/// Split into five single-table versions (rather than one big v1) so the
/// migration tests have real intermediate versions to exercise, not just
/// v0 -> v1.
pub const MIGRATIONS: &[(u32, &str)] = &[
    (
        1,
        r#"
        CREATE TABLE jobs (
            job_id          TEXT PRIMARY KEY,
            -- Natural/idempotency key: one logical transfer per
            -- (device_id, session_id, revision). A second enqueue attempt
            -- for the same logical transfer must not silently create a
            -- second job row — the retired journal's reject-not-upsert
            -- contract is preserved for compatibility with old files.
            idempotency_key TEXT NOT NULL UNIQUE,
            device_id       TEXT NOT NULL,
            session_id      TEXT NOT NULL,
            revision        TEXT NOT NULL,
            state           TEXT NOT NULL CHECK (state IN (
                                'queued',
                                'waiting_for_device',
                                'waiting_for_pairing',
                                'paused_capture_active',
                                'preparing',
                                'transferring',
                                'verifying',
                                'committing',
                                'retry_wait',
                                'cancelling',
                                'succeeded',
                                'failed',
                                'cancelled'
                            )),
            -- Only meaningful (and only allowed to be non-NULL) when
            -- state = 'failed', per plan 5.4's `failed(code, retryable)`.
            error_code      TEXT,
            error_retryable INTEGER,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            CHECK ((state = 'failed') = (error_code IS NOT NULL)),
            CHECK ((state = 'failed') = (error_retryable IS NOT NULL))
        );
        "#,
    ),
    (
        2,
        r#"
        -- Per-job, per-file download progress (plan 9.2 step 3: "写 .part，
        -- journal 保存已确认 offset、预期 size/hash/ETag"). `confirmed_offset`
        -- is the *trusted* byte count the journal has durably recorded as
        -- verified-on-disk so far -- never derived from DOM-supplied bytes,
        -- per plan 9.2's "不信任 DOM 传入 bytes/path".
        CREATE TABLE checkpoints (
            job_id           TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
            file_id          TEXT NOT NULL,
            confirmed_offset INTEGER NOT NULL DEFAULT 0,
            expected_size    INTEGER NOT NULL,
            expected_sha256  TEXT,
            expected_etag    TEXT,
            updated_at       TEXT NOT NULL,
            PRIMARY KEY (job_id, file_id),
            CHECK (confirmed_offset >= 0 AND confirmed_offset <= expected_size)
        );
        "#,
    ),
    (
        3,
        r#"
        -- local_verified / object_store_verified receipts (plan 5.1's
        -- `locally_verified` / `object_store_verified` milestones; 9.3's
        -- "只有全部对象及最终 manifest 验证后写 object_store_verified receipt").
        -- `evidence` is a JSON blob of non-secret, server-observed proof
        -- (ETag, S3 version ID, HEAD response digest) -- never a credential.
        CREATE TABLE receipts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id      TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
            kind        TEXT NOT NULL CHECK (kind IN ('local_verified', 'object_store_verified')),
            verified_at TEXT NOT NULL,
            evidence    TEXT NOT NULL,
            UNIQUE (job_id, kind)
        );
        "#,
    ),
    (
        4,
        r#"
        -- A downloaded, locally-verified session (plan 5.1's
        -- `locally_verified` milestone: "全部文件 size/hash 验证、fsync、
        -- 目录原子提交完成"). `verified` only ever flips to true inside the
        -- same commit that would also be writing the last `files` row and
            -- the `local_verified` receipt -- enforced by the retired
            -- journal writer, not by SQL alone. These tables are retained
            -- only so old files can be opened without losing their schema.
        CREATE TABLE library (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id     TEXT NOT NULL,
            session_id    TEXT NOT NULL,
            revision      TEXT NOT NULL,
            captured_at   TEXT NOT NULL,
            downloaded_at TEXT NOT NULL,
            local_path    TEXT NOT NULL,
            verified      INTEGER NOT NULL DEFAULT 0,
            UNIQUE (device_id, session_id, revision)
        );
        "#,
    ),
    (
        5,
        r#"
        -- Per-file records within a library entry (plan 9.1's publication
        -- manifest `files[]` shape: id/role/size/sha256, plus the local
        -- relative path PC-04's download engine actually wrote to).
        CREATE TABLE files (
            library_id     INTEGER NOT NULL REFERENCES library(id) ON DELETE CASCADE,
            file_id        TEXT NOT NULL,
            role           TEXT NOT NULL,
            size_bytes     INTEGER NOT NULL,
            sha256         TEXT NOT NULL,
            local_rel_path TEXT NOT NULL,
            PRIMARY KEY (library_id, file_id)
        );
        "#,
    ),
    // -----------------------------------------------------------------
    // Commit 22: the versioned job-spec + file-ledger schema `TransferStore`
    // owns. These tables live alongside (not instead of) `jobs`/
    // `checkpoints` above -- production writes still go to the old tables
    // until the enqueue path is switched over in a later commit, so a
    // rollback of that switch does not need a down-migration.
    //
    // Split one table per version, same as v1..v5, so the migration tests
    // have real intermediate versions to replay from.
    // -----------------------------------------------------------------
    (
        6,
        r#"
        -- Job identity + durable state/version. `natural_key` is the
        -- canonical length-prefixed encoding of `domain::JobIdentity`
        -- (device, session, revision) -- the UNIQUE index here is what makes
        -- "one logical transfer, one row" a database fact rather than a
        -- convention. `request_digest` is `JobSpec::request_digest` and is
        -- what commit 24 compares an incoming request against.
        CREATE TABLE transfer_jobs (
            job_id          TEXT PRIMARY KEY,
            natural_key     TEXT NOT NULL UNIQUE,
            device_id       TEXT NOT NULL,
            session_id      TEXT NOT NULL,
            revision        TEXT NOT NULL,
            request_digest  TEXT NOT NULL CHECK (length(request_digest) = 64),
            state           TEXT NOT NULL CHECK (state IN (
                                'queued',
                                'waiting_for_device',
                                'waiting_for_pairing',
                                'paused_capture_active',
                                'preparing',
                                'transferring',
                                'verifying',
                                'committing',
                                'retry_wait',
                                'cancelling',
                                'succeeded',
                                'failed',
                                'cancelled'
                            )),
            -- Monotonic per-job version, for the expected-version CAS a
            -- later commit adds. Created at 1.
            state_version   INTEGER NOT NULL DEFAULT 1 CHECK (state_version >= 1),
            error_code      TEXT,
            error_retryable INTEGER,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            CHECK ((state = 'failed') = (error_code IS NOT NULL)),
            CHECK ((state = 'failed') = (error_retryable IS NOT NULL))
        );
        CREATE INDEX transfer_jobs_state_idx ON transfer_jobs (state);
        "#,
    ),
    (
        7,
        r#"
        -- The non-file half of a `domain::JobSpec`, versioned by
        -- `spec_version` so a future spec shape can be told apart from this
        -- one instead of being silently misread. Exactly one row per job:
        -- a job without this row has no spec and is `RecoveryBlocked`, never
        -- silently skipped.
        CREATE TABLE transfer_job_specs (
            job_id                 TEXT PRIMARY KEY
                                   REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            spec_version           INTEGER NOT NULL CHECK (spec_version >= 1),
            full_session           INTEGER NOT NULL CHECK (full_session IN (0, 1)),
            date_label             TEXT NOT NULL,
            publication_revision   TEXT NOT NULL,
            -- Signed, non-secret publication material (the exact bytes that
            -- were signed, the signature, and the SAS-confirmed public key).
            -- No credential ever gets a column here -- see the module doc.
            publication_payload    BLOB NOT NULL CHECK (length(publication_payload) > 0),
            publication_signature  BLOB NOT NULL CHECK (length(publication_signature) = 64),
            publication_public_key BLOB NOT NULL CHECK (length(publication_public_key) = 32)
        );
        "#,
    ),
    (
        8,
        r#"
        -- The ordered file plan. One row per file of the *signed inventory*;
        -- `request_index` is non-NULL exactly for the files this job
        -- transfers, and carries their request order. Two UNIQUE indexes
        -- keep both orders dense and unambiguous (SQLite treats NULLs as
        -- distinct, so unrequested files do not collide on request_index).
        CREATE TABLE transfer_job_files (
            job_id          TEXT NOT NULL REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            inventory_index INTEGER NOT NULL CHECK (inventory_index >= 0),
            request_index   INTEGER CHECK (request_index IS NULL OR request_index >= 0),
            file_id         TEXT NOT NULL,
            display_path    TEXT NOT NULL,
            size_bytes      INTEGER NOT NULL CHECK (size_bytes >= 0),
            sha256          TEXT NOT NULL CHECK (length(sha256) = 64),
            PRIMARY KEY (job_id, file_id),
            UNIQUE (job_id, inventory_index),
            UNIQUE (job_id, request_index)
        );
        "#,
    ),
    (
        9,
        r#"
        -- Per-file evidence ledger. Created alongside the job with every
        -- requested file at 'missing'/0 bytes, so recovery never has to
        -- guess whether a file was "never started" or "lost its row".
        -- `verified_sha256` is the digest actually recomputed from local
        -- bytes -- present iff the file is verified.
        CREATE TABLE transfer_file_ledger (
            job_id          TEXT NOT NULL,
            file_id         TEXT NOT NULL,
            status          TEXT NOT NULL CHECK (status IN (
                                'missing', 'partial', 'verified', 'invalid'
                            )),
            bytes_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (bytes_confirmed >= 0),
            verified_sha256 TEXT,
            updated_at      TEXT NOT NULL,
            PRIMARY KEY (job_id, file_id),
            FOREIGN KEY (job_id, file_id)
                REFERENCES transfer_job_files(job_id, file_id) ON DELETE CASCADE,
            CHECK ((status = 'verified') = (verified_sha256 IS NOT NULL))
        );
        "#,
    ),
    (
        10,
        r#"
        -- One row per completed one-shot data migration (commit 26's legacy
        -- sidecar import). Written inside the same transaction as the rows
        -- it describes, so "the import ran" and "the import's rows exist"
        -- can never disagree.
        CREATE TABLE transfer_migration_markers (
            marker     TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL,
            detail     TEXT NOT NULL
        );
        "#,
    ),
    (
        11,
        r#"
        -- Commit 29: the durable completion outbox.
        --
        -- A job's terminal transition (`transfer_jobs.state` +
        -- `state_version`) and the outcome the rest of the app has to learn
        -- about are written in **one** transaction into this table, so a
        -- crash between "the job finished" and "the app learned about it"
        -- cannot lose the result: the row is still here on the next start.
        --
        -- `acknowledged_at IS NULL` *is* the queue. A row is only stamped
        -- once a consumer has durably applied the outcome (commit 30), and
        -- the row is kept afterwards rather than deleted so a re-delivered
        -- ack is a no-op instead of resurrecting the entry.
        --
        -- `UNIQUE (job_id)` is what makes recording the same terminal
        -- outcome twice idempotent rather than a second delivery, and
        -- `state_version` pins the row to the exact transition that
        -- produced it, so a consumer can tell a re-delivery from a new fact.
        CREATE TABLE transfer_completion_outbox (
            sequence        INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id          TEXT NOT NULL UNIQUE
                            REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            outcome         TEXT NOT NULL CHECK (outcome IN (
                                'succeeded', 'failed', 'cancelled'
                            )),
            error_code      TEXT,
            error_retryable INTEGER,
            state_version   INTEGER NOT NULL CHECK (state_version >= 1),
            recorded_at     TEXT NOT NULL,
            acknowledged_at TEXT,
            CHECK ((outcome = 'failed') = (error_code IS NOT NULL)),
            CHECK ((outcome = 'failed') = (error_retryable IS NOT NULL))
        );
        CREATE INDEX transfer_completion_outbox_unacked_idx
            ON transfer_completion_outbox (acknowledged_at, sequence);
        "#,
    ),
    (
        12,
        r#"
        -- Commit 35: the durable pending-upload context.
        --
        -- This replaces `pending-uploads.json`, a whole-file JSON
        -- read-modify-write that was the *only* record of multipart uploads
        -- really existing on a remote object store. A crash between the
        -- read and the rename lost that record, and with it the ability to
        -- ever abort the orphan parts it described.
        --
        -- The primary key is the multipart handle itself
        -- `(object_key, upload_id)`: that pair is exactly what an abort or a
        -- completion has to address, so "one row per real remote multipart
        -- upload" is a database fact rather than a convention.
        --
        -- `desired_state` is the durable half of the intent the in-memory
        -- `UploadOperation` token owns: 'running' means the owning task is
        -- expected to finish it, 'aborting' means the next process that can
        -- reach the object store must tear it down. A record found at
        -- startup is by definition owned by a dead process, so startup flips
        -- it to 'aborting' transactionally instead of rebuilding a JSON file.
        --
        -- ## No secrets in this table
        --
        -- `endpoint`/`bucket`/`object_key`/`upload_id` are non-secret
        -- coordinates that only *address* an upload; they authenticate
        -- nothing. The Access Key / Secret Key stay in the OS credential
        -- vault, exactly as the retired sidecar's contract already required.
        CREATE TABLE transfer_uploads (
            object_key    TEXT NOT NULL CHECK (length(object_key) > 0),
            upload_id     TEXT NOT NULL CHECK (length(upload_id) > 0),
            -- The in-memory `Transfer::key` this upload belongs to.
            transfer_key  TEXT NOT NULL CHECK (length(transfer_key) > 0),
            -- `LibraryEntry::key()` ("{device_id}|{session_id}").
            entry_key     TEXT NOT NULL,
            -- The publication revision the upload was started for. Empty
            -- only for a record imported from the legacy sidecar, which had
            -- no column for it.
            revision      TEXT NOT NULL,
            endpoint      TEXT NOT NULL,
            bucket        TEXT NOT NULL CHECK (length(bucket) > 0),
            desired_state TEXT NOT NULL CHECK (desired_state IN ('running', 'aborting')),
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL,
            PRIMARY KEY (object_key, upload_id)
        );
        CREATE INDEX transfer_uploads_transfer_idx ON transfer_uploads (transfer_key);
        CREATE INDEX transfer_uploads_desired_idx ON transfer_uploads (desired_state);
        "#,
    ),
    (
        13,
        r#"
        -- Commit 35: the parts of an in-flight multipart upload.
        --
        -- One row per part S3 has acknowledged. A part's `etag`/`size_bytes`
        -- are what `CompleteMultipartUpload` has to replay verbatim, so they
        -- are written once and never rewritten (`TransferStore::
        -- record_upload_part` rejects a second, different value for the same
        -- part number rather than overwriting it -- the same
        -- immutable-evidence rule the file ledger already follows).
        CREATE TABLE transfer_upload_parts (
            object_key  TEXT NOT NULL,
            upload_id   TEXT NOT NULL,
            part_number INTEGER NOT NULL CHECK (part_number >= 1),
            etag        TEXT NOT NULL CHECK (length(etag) > 0),
            size_bytes  INTEGER NOT NULL CHECK (size_bytes >= 0),
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (object_key, upload_id, part_number),
            FOREIGN KEY (object_key, upload_id)
                REFERENCES transfer_uploads(object_key, upload_id) ON DELETE CASCADE
        );
        "#,
    ),
    (
        14,
        r#"
        -- Commit 27/28/45: move the coordinator's user intent and retry
        -- lineage into the same durable transfer authority. The old
        -- sidecar carried `desired_run_state`; it is an input for a later
        -- migration, never a runtime source of truth.
        ALTER TABLE transfer_jobs ADD COLUMN desired_run_state TEXT NOT NULL DEFAULT 'run'
            CHECK (desired_run_state IN ('run', 'paused'));

        -- A retry is a new attempt, while the failed parent remains an
        -- auditable terminal row. The child id is unique, and `(parent,
        -- attempt)` is the durable duplicate-retry fence.
        CREATE TABLE transfer_job_lineage (
            child_job_id  TEXT PRIMARY KEY
                          REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            parent_job_id TEXT NOT NULL
                          REFERENCES transfer_jobs(job_id) ON DELETE RESTRICT,
            attempt       INTEGER NOT NULL CHECK (attempt >= 1),
            created_at    TEXT NOT NULL,
            UNIQUE (parent_job_id, attempt)
        );
        CREATE INDEX transfer_job_lineage_parent_idx
            ON transfer_job_lineage (parent_job_id, attempt);
        CREATE INDEX transfer_job_lineage_child_idx
            ON transfer_job_lineage (child_job_id);
        "#,
    ),
    (
        15,
        r#"
        -- Durable tagged upload jobs. Existing rows are downloads by
        -- default; upload rows are never eligible for the download
        -- recovery/dispatcher lane.
        ALTER TABLE transfer_jobs ADD COLUMN operation_kind TEXT NOT NULL DEFAULT 'download'
            CHECK (operation_kind IN ('download', 'upload'));

        -- The immutable input that identifies an upload attempt. The
        -- natural key is the library entry plus publication revision;
        -- input_digest distinguishes a replay from a conflicting request.
        CREATE TABLE transfer_upload_job_specs (
            job_id       TEXT PRIMARY KEY
                         REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            entry_key    TEXT NOT NULL CHECK (length(entry_key) > 0),
            revision     TEXT NOT NULL CHECK (length(revision) > 0),
            input_digest TEXT NOT NULL CHECK (length(input_digest) > 0)
        );
        CREATE INDEX transfer_upload_job_specs_entry_idx
            ON transfer_upload_job_specs (entry_key, revision);

        -- Legacy pending-upload rows predate durable jobs, so their job_id
        -- is nullable. New rows created through begin_upload_for_job always
        -- carry the upload job foreign key.
        ALTER TABLE transfer_uploads ADD COLUMN job_id TEXT
            REFERENCES transfer_jobs(job_id) ON DELETE CASCADE;
        CREATE INDEX transfer_uploads_job_idx ON transfer_uploads (job_id);

        -- Keep operation provenance with the completion evidence. Old
        -- outbox rows were download completions and receive the safe default.
        ALTER TABLE transfer_completion_outbox ADD COLUMN operation_kind TEXT NOT NULL DEFAULT 'download'
            CHECK (operation_kind IN ('download', 'upload'));
        "#,
    ),
    (
        16,
        r#"
        -- Durable visibility is a property of the job, not of a particular
        -- UI lane. Dismissal is a tombstone: jobs, specs, retry lineage,
        -- completion evidence and audit history remain addressable.
        ALTER TABLE transfer_jobs ADD COLUMN dismissed_at TEXT;

        -- Mutable upload activity projection. The upload job spec remains
        -- immutable request identity; multipart rows remain remote evidence
        -- and may be removed once an object is completed or aborted.
        CREATE TABLE transfer_upload_activity (
            job_id          TEXT PRIMARY KEY
                            REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            label           TEXT NOT NULL,
            target_label    TEXT NOT NULL,
            total_bytes     INTEGER NOT NULL DEFAULT 0 CHECK (total_bytes >= 0),
            confirmed_bytes INTEGER NOT NULL DEFAULT 0 CHECK (confirmed_bytes >= 0),
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            CHECK (total_bytes = 0 OR confirmed_bytes <= total_bytes)
        );
        CREATE INDEX transfer_upload_activity_updated_idx
            ON transfer_upload_activity (updated_at, job_id);

        -- v15 upload jobs did not have display metadata or a durable
        -- aggregate. Preserve every request with lossless identity fallback;
        -- a zero total means "unknown" and avoids inventing progress from
        -- old part rows (which also contain evidence/manifest parts).
        INSERT INTO transfer_upload_activity (
            job_id, label, target_label, total_bytes, confirmed_bytes,
            created_at, updated_at
        )
        SELECT j.job_id,
               s.entry_key,
               COALESCE((
                   SELECT u.bucket
                   FROM transfer_uploads u
                   WHERE u.job_id = j.job_id
                   ORDER BY u.updated_at DESC, u.object_key DESC, u.upload_id DESC
                   LIMIT 1
               ), ''),
               0,
               0,
               j.created_at,
               j.updated_at
        FROM transfer_jobs j
        JOIN transfer_upload_job_specs s ON s.job_id = j.job_id
        WHERE j.operation_kind = 'upload';
        "#,
    ),
    (
        17,
        r#"
        -- Durable, HEAD-verified evidence for an upload job. These rows are
        -- deliberately separate from `transfer_uploads`: multipart handles
        -- may be retired after a remote completion or abort, while verified
        -- object receipts remain the durable accounting needed by the upload
        -- completion outbox and by recovery after a crash.
        --
        -- `entry_key` and `revision` are copied from the immutable upload job
        -- spec at staging time. The API checks that copy against the spec in
        -- the same transaction, so a receipt can never be attached to a
        -- different library entry or publication revision by accident.
        -- `object_role` distinguishes signed data files from publication /
        -- verification evidence; it is not inferred from an object-key
        -- suffix. A receipt is immutable once staged: replaying the same
        -- row is idempotent, but any changed proof is a conflict.
        CREATE TABLE transfer_upload_receipts (
            job_id          TEXT NOT NULL
                            REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            entry_key       TEXT NOT NULL CHECK (length(entry_key) > 0),
            revision        TEXT NOT NULL CHECK (length(revision) > 0),
            object_key      TEXT NOT NULL CHECK (length(object_key) > 0),
            object_role     TEXT NOT NULL CHECK (object_role IN ('data', 'evidence')),
            etag            TEXT NOT NULL CHECK (length(etag) > 0),
            version_id      TEXT,
            size_bytes      INTEGER NOT NULL CHECK (size_bytes >= 0),
            source_sha256   TEXT NOT NULL CHECK (length(source_sha256) = 64),
            digest_proof    TEXT NOT NULL CHECK (
                                digest_proof IN ('server_checksum', 'streamed_readback')
                            ),
            staged_at       TEXT NOT NULL,
            PRIMARY KEY (job_id, object_key)
        );
        CREATE INDEX transfer_upload_receipts_revision_idx
            ON transfer_upload_receipts (entry_key, revision, object_role, object_key);
        "#,
    ),
    (
        18,
        r#"
        -- Persist the S3-compatible URL addressing style with each
        -- multipart handle. The style is part of the request identity: a
        -- restart must use the style selected when the remote upload was
        -- created, even if the current storage configuration changed.
        -- Existing rows predate this column and therefore cannot prove which
        -- style was used to create the remote handle. Mark them explicitly
        -- as legacy-configured so recovery may use the current setting for
        -- those rows only. Legacy JSON imports carry the same explicit
        -- uncertainty marker in `legacy_import.rs`.
        ALTER TABLE transfer_uploads ADD COLUMN url_style TEXT NOT NULL DEFAULT 'legacy_configured'
            CHECK (url_style IN ('virtual_host', 'path', 'legacy_configured'));
        "#,
    ),
    (
        19,
        r#"
        -- The destination namespace is part of an upload job's immutable
        -- context. New jobs persist the normalized object-key prefix so a
        -- completion receipt can be checked against the full key rather
        -- than only a collision-prone suffix. Existing rows predate this
        -- proof and retain an explicit NULL/unknown value.
        ALTER TABLE transfer_upload_job_specs ADD COLUMN object_prefix TEXT
            CHECK (object_prefix IS NULL OR length(object_prefix) >= 0);
        "#,
    ),
    (
        20,
        r#"
        -- Derived-bundle uploads share the upload job machinery but not its
        -- natural key. A legacy upload is identified by (library entry key,
        -- publication revision); a derived-bundle upload is identified by
        -- (upload bundle revision, storage profile identity), because the same
        -- frozen bundle sent to a different bucket/prefix/endpoint is a
        -- different upload, and the same destination for a changed bundle is a
        -- conflict. Collapsing the two would let one silently satisfy the
        -- other, so the subject is made explicit and typed.
        ALTER TABLE transfer_upload_job_specs
            ADD COLUMN subject_kind TEXT NOT NULL DEFAULT 'library_publication'
            CHECK (subject_kind IN ('library_publication', 'derived_bundle'));

        ALTER TABLE transfer_upload_job_specs
            ADD COLUMN storage_profile_identity TEXT
            CHECK (storage_profile_identity IS NULL OR length(storage_profile_identity) > 0);

        CREATE INDEX transfer_derived_upload_natural_key
            ON transfer_upload_job_specs (revision, storage_profile_identity)
            WHERE subject_kind = 'derived_bundle';

        -- Composite target for the sidecar's foreign key, so a sidecar can
        -- never describe a different bundle or destination than its spec.
        CREATE UNIQUE INDEX transfer_upload_subject_context
            ON transfer_upload_job_specs (job_id, revision, storage_profile_identity);

        -- The discriminator and the storage identity must agree in both
        -- directions: a derived bundle always has a destination identity, and
        -- a library publication never does.
        CREATE TRIGGER transfer_upload_subject_insert_guard
        BEFORE INSERT ON transfer_upload_job_specs
        WHEN (NEW.subject_kind = 'derived_bundle' AND NEW.storage_profile_identity IS NULL)
          OR (NEW.subject_kind = 'library_publication' AND NEW.storage_profile_identity IS NOT NULL)
        BEGIN
            SELECT RAISE(ABORT, 'upload subject/storage profile mismatch');
        END;

        CREATE TRIGGER transfer_upload_subject_update_guard
        BEFORE UPDATE OF subject_kind, storage_profile_identity ON transfer_upload_job_specs
        WHEN (NEW.subject_kind = 'derived_bundle' AND NEW.storage_profile_identity IS NULL)
          OR (NEW.subject_kind = 'library_publication' AND NEW.storage_profile_identity IS NOT NULL)
        BEGIN
            SELECT RAISE(ABORT, 'upload subject/storage profile mismatch');
        END;

        -- Frozen bundle plus multipart checkpoint sidecar. The bundle is
        -- immutable for the lifetime of the attempt; the checkpoint advances
        -- under its own version CAS so two workers cannot overwrite each
        -- other's durable multipart handles, parts, or verified receipts.
        CREATE TABLE transfer_derived_upload_jobs (
            job_id                    TEXT PRIMARY KEY
                                      REFERENCES transfer_jobs(job_id) ON DELETE CASCADE,
            media_library_entry_key   TEXT NOT NULL CHECK (length(media_library_entry_key) > 0),
            upload_bundle_revision    TEXT NOT NULL CHECK (length(upload_bundle_revision) > 0),
            storage_profile_identity  TEXT NOT NULL CHECK (length(storage_profile_identity) > 0),
            frozen_bundle_json        TEXT NOT NULL CHECK (json_valid(frozen_bundle_json)),
            checkpoint_json           TEXT NOT NULL CHECK (json_valid(checkpoint_json)),
            checkpoint_version        INTEGER NOT NULL CHECK (checkpoint_version >= 1),
            created_at                TEXT NOT NULL,
            updated_at                TEXT NOT NULL,
            FOREIGN KEY (job_id, upload_bundle_revision, storage_profile_identity)
                REFERENCES transfer_upload_job_specs (job_id, revision, storage_profile_identity)
        );
        CREATE INDEX transfer_derived_upload_jobs_natural_key_idx
            ON transfer_derived_upload_jobs (upload_bundle_revision, storage_profile_identity);
        "#,
    ),
];

/// The highest migration version this build knows how to apply. A store
/// file whose recorded version exceeds this was written by a newer binary
/// and must not be opened — see
/// [`PersistenceError::UnsupportedSchemaVersion`].
#[must_use]
pub fn latest_version() -> u32 {
    MIGRATIONS.iter().map(|(v, _)| *v).max().unwrap_or(0)
}

/// Per-file evidence status in `transfer_file_ledger`.
///
/// `Missing` and `Invalid` are deliberately distinct: "we have nothing"
/// and "we have bytes that failed verification" lead to different recovery
/// actions (start vs. discard-and-restart), and collapsing them is exactly
/// the ambiguity the ledger exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileLedgerStatus {
    Missing,
    Partial,
    Verified,
    Invalid,
}

impl FileLedgerStatus {
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            FileLedgerStatus::Missing => "missing",
            FileLedgerStatus::Partial => "partial",
            FileLedgerStatus::Verified => "verified",
            FileLedgerStatus::Invalid => "invalid",
        }
    }

    #[must_use]
    pub fn from_db_str(value: &str) -> Option<Self> {
        Some(match value {
            "missing" => FileLedgerStatus::Missing,
            "partial" => FileLedgerStatus::Partial,
            "verified" => FileLedgerStatus::Verified,
            "invalid" => FileLedgerStatus::Invalid,
            _ => return None,
        })
    }
}

/// `transfer_job_specs.spec_version` written by this build.
pub const CURRENT_JOB_SPEC_VERSION: u32 = 1;

/// Stable identity for the transfer-store consumer of this schema runner.
/// A database opened by another store must never be silently interpreted as
/// the transfer schema, even though both use SQLite and migrations.
pub(crate) const TRANSFER_STORE_IDENTITY: &str = "ylx-transfer/transfer-store";

// ---------------------------------------------------------------------
// Shared migration runner
// ---------------------------------------------------------------------

/// Current `schema_migrations` high-water mark, or 0 for a fresh file.
pub(crate) fn read_schema_version(
    conn: &rusqlite::Connection,
) -> Result<u32, super::error::PersistenceError> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count > 0)?;
    if !exists {
        return Ok(0);
    }
    let version: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;
    u32::try_from(version.max(0)).map_err(|_| {
        super::error::PersistenceError::corrupt(
            "<sqlite>",
            format!("schema migration version {version} does not fit u32"),
        )
    })
}

/// Applies every migration above the file's current version, each in its
/// own transaction, and records it in `schema_migrations`.
///
/// Two properties the tests pin down:
///
/// - **Idempotent.** Already-applied versions are skipped via the
///   high-water mark, and the `schema_migrations` bootstrap is
///   `IF NOT EXISTS`, so running this on an up-to-date file is a no-op.
/// - **Fail closed on the future.** A file recorded at a version above
///   [`latest_version`] is rejected with
///   [`PersistenceError::UnsupportedSchemaVersion`] *before* any DDL runs,
///   so an older binary never half-migrates a newer file.
pub(crate) fn run_migrations(
    conn: &mut rusqlite::Connection,
    path: &std::path::Path,
) -> Result<(), super::error::PersistenceError> {
    run_migrations_for(conn, path, TRANSFER_STORE_IDENTITY, MIGRATIONS)
}

/// Shared SQLite bootstrap/migration runner used by the durable transfer
/// store and AppStore's own table set. It validates the migration manifest
/// and persisted high-water mark before applying DDL:
/// missing versions, checksum drift, future versions and an identity from a
/// different store all fail closed.
pub(crate) fn run_migrations_for(
    conn: &mut rusqlite::Connection,
    path: &std::path::Path,
    identity: &str,
    migrations: &[(u32, &str)],
) -> Result<(), super::error::PersistenceError> {
    use super::error::PersistenceError;
    use rusqlite::OptionalExtension;

    validate_manifest(migrations)
        .map_err(|detail| PersistenceError::Migration { version: 0, detail })?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            checksum   TEXT,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    let mut current = read_schema_version(conn)?;
    let supported = migrations
        .iter()
        .map(|(version, _)| *version)
        .max()
        .unwrap_or(0);
    if current > supported {
        return Err(PersistenceError::UnsupportedSchemaVersion {
            path: path.to_path_buf(),
            found: current,
            supported,
        });
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_store_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )?;

    let persisted_identity: Option<String> = conn
        .query_row(
            "SELECT value FROM schema_store_meta WHERE key = 'identity'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(found) = persisted_identity {
        if found != identity {
            return Err(PersistenceError::corrupt(
                path,
                format!("store identity {found:?} does not match requested {identity:?}"),
            ));
        }
    } else {
        conn.execute(
            "INSERT INTO schema_store_meta (key, value) VALUES ('identity', ?1)",
            [identity],
        )?;
    }

    // Databases created by the pre-CAS runner have no checksum column. Add
    // it in place and backfill below; this preserves old rows while making
    // all subsequent opens checksum-checked.
    let migration_columns = table_columns(conn, "schema_migrations")?;
    if !migration_columns.iter().any(|column| column == "checksum") {
        conn.execute("ALTER TABLE schema_migrations ADD COLUMN checksum TEXT", [])?;
    }

    let mut rows = Vec::new();
    {
        let mut statement =
            conn.prepare("SELECT version, checksum FROM schema_migrations ORDER BY version ASC")?;
        let mapped = statement.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        for row in mapped {
            rows.push(row?);
        }
    }

    // A high-water mark alone is insufficient: a deleted middle migration
    // would make a newer schema appear valid. Verify every persisted version
    // is known and that all versions up to the high-water mark are present.
    for (raw_version, checksum) in &rows {
        let version = u32::try_from(*raw_version).map_err(|_| {
            PersistenceError::corrupt(path, format!("invalid migration version {raw_version}"))
        })?;
        let Some((_, sql)) = migrations
            .iter()
            .find(|(candidate, _)| *candidate == version)
        else {
            return Err(PersistenceError::UnsupportedSchemaVersion {
                path: path.to_path_buf(),
                found: version,
                supported,
            });
        };
        let expected = migration_checksum(sql);
        match checksum {
            Some(actual) if actual != &expected => {
                return Err(PersistenceError::corrupt(
                    path,
                    format!("migration {version} checksum mismatch"),
                ));
            }
            Some(_) => {}
            None => {
                // Legacy rows predate checksums. Record the checksum before
                // applying any new migration so future opens can detect
                // drift while preserving the existing data.
                conn.execute(
                    "UPDATE schema_migrations SET checksum = ?1 WHERE version = ?2",
                    rusqlite::params![expected, i64::from(version)],
                )?;
            }
        }
    }
    for expected_version in 1..=current {
        if !rows
            .iter()
            .any(|(version, _)| *version == i64::from(expected_version))
        {
            return Err(PersistenceError::Migration {
                version: expected_version,
                detail: "schema migration history is missing a prior version".to_string(),
            });
        }
    }

    for (version, sql) in migrations {
        if *version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)
            .map_err(|e| PersistenceError::Migration {
                version: *version,
                detail: e.to_string(),
            })?;
        tx.execute(
            "INSERT INTO schema_migrations (version, checksum) VALUES (?1, ?2)",
            rusqlite::params![*version, migration_checksum(sql)],
        )
        .map_err(|e| PersistenceError::Migration {
            version: *version,
            detail: e.to_string(),
        })?;
        tx.commit()?;
        current = *version;
    }
    Ok(())
}

fn validate_manifest(migrations: &[(u32, &str)]) -> Result<(), String> {
    let mut expected = 1u32;
    for (version, _) in migrations {
        if *version != expected {
            return Err(format!(
                "migration manifest is not contiguous: expected version {expected}, found {version}"
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| "migration manifest version overflow".to_string())?;
    }
    Ok(())
}

fn migration_checksum(sql: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(sql.as_bytes());
    format!("{:x}", digest.finalize())
}

fn table_columns(
    conn: &rusqlite::Connection,
    table: &str,
) -> Result<Vec<String>, super::error::PersistenceError> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns)
}

/// The tagged job-state enum from plan section 5.4, without payload
/// (payload -- `error_code`/`retryable` -- lives alongside this tag in
/// the durable transfer-job row, not inside the tag itself, so the transition
/// graph below can stay a simple finite-state matcher).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobStateTag {
    Queued,
    WaitingForDevice,
    WaitingForPairing,
    PausedCaptureActive,
    Preparing,
    Transferring,
    Verifying,
    Committing,
    RetryWait,
    Cancelling,
    Succeeded,
    Failed,
    Cancelled,
}

impl JobStateTag {
    pub fn as_db_str(self) -> &'static str {
        match self {
            JobStateTag::Queued => "queued",
            JobStateTag::WaitingForDevice => "waiting_for_device",
            JobStateTag::WaitingForPairing => "waiting_for_pairing",
            JobStateTag::PausedCaptureActive => "paused_capture_active",
            JobStateTag::Preparing => "preparing",
            JobStateTag::Transferring => "transferring",
            JobStateTag::Verifying => "verifying",
            JobStateTag::Committing => "committing",
            JobStateTag::RetryWait => "retry_wait",
            JobStateTag::Cancelling => "cancelling",
            JobStateTag::Succeeded => "succeeded",
            JobStateTag::Failed => "failed",
            JobStateTag::Cancelled => "cancelled",
        }
    }

    pub fn from_db_str(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => JobStateTag::Queued,
            "waiting_for_device" => JobStateTag::WaitingForDevice,
            "waiting_for_pairing" => JobStateTag::WaitingForPairing,
            "paused_capture_active" => JobStateTag::PausedCaptureActive,
            "preparing" => JobStateTag::Preparing,
            "transferring" => JobStateTag::Transferring,
            "verifying" => JobStateTag::Verifying,
            "committing" => JobStateTag::Committing,
            "retry_wait" => JobStateTag::RetryWait,
            "cancelling" => JobStateTag::Cancelling,
            "succeeded" => JobStateTag::Succeeded,
            "failed" => JobStateTag::Failed,
            "cancelled" => JobStateTag::Cancelled,
            _ => return None,
        })
    }

    /// True for states that never transition further. `Failed` and
    /// `Cancelled` are terminal in this draft graph: a retry after failure
    /// is modeled as a *new* job (fresh `idempotency_key`, e.g. a new
    /// revision attempt), not a resurrection of the old row -- this keeps
    /// "one job, one lifecycle, one row" invariant explicit.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobStateTag::Succeeded | JobStateTag::Failed | JobStateTag::Cancelled
        )
    }
}

/// Persisted transition graph for the compatibility job tables. Every edge is
/// intentional; terminal rows are immutable and retries receive a new job.
pub fn is_valid_transition(from: JobStateTag, to: JobStateTag) -> bool {
    use JobStateTag::*;
    if from.is_terminal() {
        return false;
    }
    matches!(
        (from, to),
        (Queued, WaitingForDevice)
            | (Queued, WaitingForPairing)
            | (Queued, Preparing)
            | (Queued, Cancelling)
            | (WaitingForDevice, Queued)
            | (WaitingForDevice, Preparing)
            | (WaitingForDevice, PausedCaptureActive)
            | (WaitingForDevice, Cancelling)
            | (WaitingForPairing, Queued)
            | (WaitingForPairing, Preparing)
            | (WaitingForPairing, Cancelling)
            | (PausedCaptureActive, Queued)
            | (PausedCaptureActive, Preparing)
            | (PausedCaptureActive, Cancelling)
            | (Preparing, Transferring)
            | (Preparing, WaitingForDevice)
            | (Preparing, Failed)
            | (Preparing, Cancelling)
            | (Transferring, Verifying)
            | (Transferring, RetryWait)
            | (Transferring, PausedCaptureActive)
            | (Transferring, Failed)
            | (Transferring, Cancelling)
            | (Verifying, Committing)
            | (Verifying, RetryWait)
            | (Verifying, Failed)
            | (Verifying, Cancelling)
            | (Committing, Succeeded)
            | (Committing, RetryWait)
            | (Committing, Failed)
            | (RetryWait, Queued)
            | (RetryWait, Preparing)
            | (RetryWait, Cancelling)
            | (RetryWait, Failed)
            | (Cancelling, Cancelled)
            | (Cancelling, Failed)
    )
}
