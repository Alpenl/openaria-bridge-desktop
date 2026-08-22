use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};

use super::error::MediaStoreError;
use super::model::{
    AcquireLeaseOutcome, AcquireLibraryLease, LibraryLeaseMode, LibraryRevisionKind,
    LibraryRevisionLease, ReleaseLeaseOutcome,
};
use super::store::{checked_i64, checked_u64, require_non_empty, MediaStore};

impl MediaStore {
    /// Acquires a shared read or exclusive publish/delete lease.
    ///
    /// Conflict detection, expired-row cleanup, fencing-token allocation and
    /// insertion run under one `BEGIN IMMEDIATE` transaction. Different
    /// processes therefore cannot both observe an empty lease set and win.
    pub fn acquire_library_revision_lease(
        &mut self,
        request: &AcquireLibraryLease<'_>,
    ) -> Result<AcquireLeaseOutcome, MediaStoreError> {
        validate_request(request)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        delete_expired_for_revision(
            &tx,
            request.revision_kind,
            request.revision_id,
            request.now_ms,
        )?;

        if let Some(existing) = read_lease(&tx, request.lease_id)? {
            if existing.revision_kind == request.revision_kind
                && existing.revision_id == request.revision_id
                && existing.owner_id == request.owner_id
                && existing.mode == request.mode
                && existing.expires_at_ms == request.expires_at_ms
            {
                tx.commit()?;
                return Ok(AcquireLeaseOutcome::Existing(existing));
            }
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "lease id {:?} is already bound to another request",
                    request.lease_id
                ),
            });
        }

        let conflicts = active_conflicts(
            &tx,
            request.revision_kind,
            request.revision_id,
            request.mode,
            request.now_ms,
        )?;
        if !conflicts.is_empty() {
            tx.commit()?;
            return Ok(AcquireLeaseOutcome::Conflict(conflicts));
        }

        tx.execute(
            "INSERT INTO media_library_lease_epochs (
                 revision_kind, revision_id, last_fencing_token
             ) VALUES (?1, ?2, 0)
             ON CONFLICT (revision_kind, revision_id) DO NOTHING",
            rusqlite::params![request.revision_kind.as_db_str(), request.revision_id],
        )?;
        let changed = tx.execute(
            "UPDATE media_library_lease_epochs
             SET last_fencing_token = last_fencing_token + 1
             WHERE revision_kind = ?1 AND revision_id = ?2
               AND last_fencing_token < 9223372036854775807",
            rusqlite::params![request.revision_kind.as_db_str(), request.revision_id],
        )?;
        if changed != 1 {
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "fencing token range exhausted for {} revision {:?}",
                    request.revision_kind.as_db_str(),
                    request.revision_id
                ),
            });
        }
        let fencing_token: i64 = tx.query_row(
            "SELECT last_fencing_token FROM media_library_lease_epochs
             WHERE revision_kind = ?1 AND revision_id = ?2",
            rusqlite::params![request.revision_kind.as_db_str(), request.revision_id],
            |row| row.get(0),
        )?;
        let fencing_token = checked_u64(
            fencing_token,
            "media_library_lease_epochs",
            "last_fencing_token",
        )?;
        tx.execute(
            "INSERT INTO media_library_revision_leases (
                 lease_id, revision_kind, revision_id, owner_id, lease_mode,
                 fencing_token, acquired_at, updated_at, expires_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)",
            rusqlite::params![
                request.lease_id,
                request.revision_kind.as_db_str(),
                request.revision_id,
                request.owner_id,
                request.mode.as_db_str(),
                checked_i64(fencing_token, "fencing_token")?,
                request.now,
                checked_i64(request.expires_at_ms, "expires_at_ms")?,
            ],
        )?;
        let lease =
            read_lease(&tx, request.lease_id)?.ok_or_else(|| MediaStoreError::NotFound {
                detail: format!(
                    "lease {:?} vanished immediately after insertion",
                    request.lease_id
                ),
            })?;
        tx.commit()?;
        Ok(AcquireLeaseOutcome::Acquired(lease))
    }

    /// Extends a lease only while the caller still owns its fencing token.
    /// An expired lease is never resurrected; callers must acquire again and
    /// receive a newer fencing token.
    pub fn renew_library_revision_lease(
        &mut self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
        now: &str,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<LibraryRevisionLease, MediaStoreError> {
        require_non_empty(lease_id, "lease_id")?;
        require_non_empty(owner_id, "owner_id")?;
        require_non_empty(now, "now")?;
        if expires_at_ms <= now_ms {
            return Err(MediaStoreError::Conflict {
                detail: "renewed lease expiry must be after now".to_string(),
            });
        }
        let changed = self.conn.execute(
            "UPDATE media_library_revision_leases
             SET updated_at = ?4, expires_at_ms = ?5
             WHERE lease_id = ?1 AND owner_id = ?2 AND fencing_token = ?3
               AND expires_at_ms > ?6",
            rusqlite::params![
                lease_id,
                owner_id,
                checked_i64(fencing_token, "fencing_token")?,
                now,
                checked_i64(expires_at_ms, "expires_at_ms")?,
                checked_i64(now_ms, "now_ms")?,
            ],
        )?;
        if changed != 1 {
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "lease {lease_id:?} is expired or no longer owned by fencing token {fencing_token}"
                ),
            });
        }
        read_lease(&self.conn, lease_id)?.ok_or_else(|| MediaStoreError::NotFound {
            detail: format!("lease {lease_id:?} vanished after renewal"),
        })
    }

    pub fn release_library_revision_lease(
        &mut self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
    ) -> Result<ReleaseLeaseOutcome, MediaStoreError> {
        require_non_empty(lease_id, "lease_id")?;
        require_non_empty(owner_id, "owner_id")?;
        let changed = self.conn.execute(
            "DELETE FROM media_library_revision_leases
             WHERE lease_id = ?1 AND owner_id = ?2 AND fencing_token = ?3",
            rusqlite::params![
                lease_id,
                owner_id,
                checked_i64(fencing_token, "fencing_token")?,
            ],
        )?;
        if changed == 1 {
            return Ok(ReleaseLeaseOutcome::Released);
        }
        if read_lease(&self.conn, lease_id)?.is_some() {
            Ok(ReleaseLeaseOutcome::OwnershipLost)
        } else {
            Ok(ReleaseLeaseOutcome::AlreadyReleased)
        }
    }

    /// Rechecks ownership immediately before a filesystem publish/delete.
    pub fn assert_library_revision_lease(
        &self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
        required_mode: LibraryLeaseMode,
        now_ms: u64,
    ) -> Result<LibraryRevisionLease, MediaStoreError> {
        let Some(lease) = read_lease(&self.conn, lease_id)? else {
            return Err(MediaStoreError::Conflict {
                detail: format!("lease {lease_id:?} no longer exists"),
            });
        };
        if lease.owner_id != owner_id
            || lease.fencing_token != fencing_token
            || lease.mode != required_mode
            || lease.expires_at_ms <= now_ms
        {
            return Err(MediaStoreError::Conflict {
                detail: format!("lease {lease_id:?} ownership or fencing check failed"),
            });
        }
        Ok(lease)
    }

    pub fn active_library_revision_leases(
        &self,
        revision_kind: LibraryRevisionKind,
        revision_id: &str,
        now_ms: u64,
    ) -> Result<Vec<LibraryRevisionLease>, MediaStoreError> {
        read_active_leases(&self.conn, revision_kind, revision_id, now_ms)
    }

    pub fn purge_expired_library_revision_leases(
        &mut self,
        now_ms: u64,
    ) -> Result<u64, MediaStoreError> {
        let changed = self.conn.execute(
            "DELETE FROM media_library_revision_leases WHERE expires_at_ms <= ?1",
            [checked_i64(now_ms, "now_ms")?],
        )?;
        u64::try_from(changed).map_err(|_| {
            MediaStoreError::corrupt(
                "media_library_revision_leases",
                "deleted row count exceeds u64",
            )
        })
    }
}

fn validate_request(request: &AcquireLibraryLease<'_>) -> Result<(), MediaStoreError> {
    require_non_empty(request.lease_id, "lease_id")?;
    require_non_empty(request.revision_id, "revision_id")?;
    require_non_empty(request.owner_id, "owner_id")?;
    require_non_empty(request.now, "now")?;
    if request.expires_at_ms <= request.now_ms {
        return Err(MediaStoreError::Conflict {
            detail: "lease expiry must be after now".to_string(),
        });
    }
    Ok(())
}

fn delete_expired_for_revision(
    tx: &Transaction<'_>,
    revision_kind: LibraryRevisionKind,
    revision_id: &str,
    now_ms: u64,
) -> Result<(), MediaStoreError> {
    tx.execute(
        "DELETE FROM media_library_revision_leases
         WHERE revision_kind = ?1 AND revision_id = ?2 AND expires_at_ms <= ?3",
        rusqlite::params![
            revision_kind.as_db_str(),
            revision_id,
            checked_i64(now_ms, "now_ms")?,
        ],
    )?;
    Ok(())
}

fn active_conflicts(
    conn: &rusqlite::Connection,
    revision_kind: LibraryRevisionKind,
    revision_id: &str,
    requested_mode: LibraryLeaseMode,
    now_ms: u64,
) -> Result<Vec<LibraryRevisionLease>, MediaStoreError> {
    let active = read_active_leases(conn, revision_kind, revision_id, now_ms)?;
    Ok(active
        .into_iter()
        .filter(|lease| {
            requested_mode == LibraryLeaseMode::Exclusive
                || lease.mode == LibraryLeaseMode::Exclusive
        })
        .collect())
}

fn read_active_leases(
    conn: &rusqlite::Connection,
    revision_kind: LibraryRevisionKind,
    revision_id: &str,
    now_ms: u64,
) -> Result<Vec<LibraryRevisionLease>, MediaStoreError> {
    let mut statement = conn.prepare(
        "SELECT lease_id, revision_kind, revision_id, owner_id, lease_mode,
                fencing_token, acquired_at, updated_at, expires_at_ms
         FROM media_library_revision_leases
         WHERE revision_kind = ?1 AND revision_id = ?2 AND expires_at_ms > ?3
         ORDER BY fencing_token, lease_id",
    )?;
    let rows = statement
        .query_map(
            rusqlite::params![
                revision_kind.as_db_str(),
                revision_id,
                checked_i64(now_ms, "now_ms")?,
            ],
            |row| Ok(read_lease_row(row)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            row.map_err(|detail| MediaStoreError::corrupt("media_library_revision_leases", detail))
        })
        .collect()
}

fn read_lease(
    conn: &rusqlite::Connection,
    lease_id: &str,
) -> Result<Option<LibraryRevisionLease>, MediaStoreError> {
    let row: Option<Result<LibraryRevisionLease, String>> = conn
        .query_row(
            "SELECT lease_id, revision_kind, revision_id, owner_id, lease_mode,
                    fencing_token, acquired_at, updated_at, expires_at_ms
             FROM media_library_revision_leases WHERE lease_id = ?1",
            [lease_id],
            |row| Ok(read_lease_row(row)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some(Ok(lease)) => Ok(Some(lease)),
        Some(Err(detail)) => Err(MediaStoreError::corrupt(
            "media_library_revision_leases",
            detail,
        )),
    }
}

fn read_lease_row(row: &rusqlite::Row<'_>) -> Result<LibraryRevisionLease, String> {
    let revision_kind: String = row.get(1).map_err(|error| error.to_string())?;
    let mode: String = row.get(4).map_err(|error| error.to_string())?;
    let fencing_token: i64 = row.get(5).map_err(|error| error.to_string())?;
    let expires_at_ms: i64 = row.get(8).map_err(|error| error.to_string())?;
    Ok(LibraryRevisionLease {
        lease_id: row.get(0).map_err(|error| error.to_string())?,
        revision_kind: LibraryRevisionKind::from_db_str(&revision_kind)
            .ok_or_else(|| format!("unknown revision kind {revision_kind:?}"))?,
        revision_id: row.get(2).map_err(|error| error.to_string())?,
        owner_id: row.get(3).map_err(|error| error.to_string())?,
        mode: LibraryLeaseMode::from_db_str(&mode)
            .ok_or_else(|| format!("unknown lease mode {mode:?}"))?,
        fencing_token: u64::try_from(fencing_token)
            .map_err(|_| format!("negative fencing token {fencing_token}"))?,
        acquired_at: row.get(6).map_err(|error| error.to_string())?,
        updated_at: row.get(7).map_err(|error| error.to_string())?,
        expires_at_ms: u64::try_from(expires_at_ms)
            .map_err(|_| format!("negative lease expiry {expires_at_ms}"))?,
    })
}
