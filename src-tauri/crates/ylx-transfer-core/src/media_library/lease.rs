use crate::media_store::{
    AcquireLeaseOutcome, AcquireLibraryLease, LibraryLeaseMode, LibraryRevisionKind,
    LibraryRevisionLease, MediaStore, MediaStoreError, ReleaseLeaseOutcome,
};

/// Consumption-side port for durable shared/exclusive immutable-tree leases.
///
/// A normalizer or uploader consumes `Shared`; source/derived publication and
/// local retention cleanup consume `Exclusive`. Implementations must recheck
/// the fencing token immediately before the protected filesystem action.
pub trait LibraryRevisionLeasePort {
    type Error;

    fn acquire_revision_lease(
        &mut self,
        request: &AcquireLibraryLease<'_>,
    ) -> Result<AcquireLeaseOutcome, Self::Error>;

    fn renew_revision_lease(
        &mut self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
        now: &str,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<LibraryRevisionLease, Self::Error>;

    /// Reasserts an active lease and binds it to the exact revision the
    /// caller is about to consume. Checking only lease id/owner/token is not
    /// sufficient because a wiring bug could otherwise authorize the wrong
    /// immutable tree.
    #[allow(clippy::too_many_arguments)]
    fn consume_revision_lease(
        &self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
        required_kind: LibraryRevisionKind,
        required_revision: &str,
        required_mode: LibraryLeaseMode,
        now_ms: u64,
    ) -> Result<LibraryRevisionLease, Self::Error>;

    fn release_revision_lease(
        &mut self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
    ) -> Result<ReleaseLeaseOutcome, Self::Error>;
}

impl LibraryRevisionLeasePort for MediaStore {
    type Error = MediaStoreError;

    fn acquire_revision_lease(
        &mut self,
        request: &AcquireLibraryLease<'_>,
    ) -> Result<AcquireLeaseOutcome, Self::Error> {
        self.acquire_library_revision_lease(request)
    }

    fn renew_revision_lease(
        &mut self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
        now: &str,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<LibraryRevisionLease, Self::Error> {
        self.renew_library_revision_lease(
            lease_id,
            owner_id,
            fencing_token,
            now,
            now_ms,
            expires_at_ms,
        )
    }

    fn consume_revision_lease(
        &self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
        required_kind: LibraryRevisionKind,
        required_revision: &str,
        required_mode: LibraryLeaseMode,
        now_ms: u64,
    ) -> Result<LibraryRevisionLease, Self::Error> {
        let lease = self.assert_library_revision_lease(
            lease_id,
            owner_id,
            fencing_token,
            required_mode,
            now_ms,
        )?;
        if lease.revision_kind != required_kind || lease.revision_id != required_revision {
            return Err(MediaStoreError::Conflict {
                detail: format!(
                    "lease {lease_id:?} targets {} revision {:?}, expected {} revision {:?}",
                    lease.revision_kind.as_db_str(),
                    lease.revision_id,
                    required_kind.as_db_str(),
                    required_revision
                ),
            });
        }
        Ok(lease)
    }

    fn release_revision_lease(
        &mut self,
        lease_id: &str,
        owner_id: &str,
        fencing_token: u64,
    ) -> Result<ReleaseLeaseOutcome, Self::Error> {
        self.release_library_revision_lease(lease_id, owner_id, fencing_token)
    }
}
