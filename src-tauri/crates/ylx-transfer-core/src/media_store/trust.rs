//! PC-owned trusted producer key registry.
//!
//! A card carries a public key and a fingerprint. Neither is evidence: the
//! only thing that makes a producer key trusted is a SAS transcript the
//! operator confirmed on this PC. This module owns that durable decision so
//! `SignedPublicationV1` media can be admitted while the producer is offline.
//!
//! The registry stores no connection token and no secret. It keeps the
//! confirmed fingerprint, a digest binding the pairing transcript, and an
//! append-only audit of confirm/rotate/revoke actions.

use rusqlite::{OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::MediaStoreError;
use super::store::MediaStore;

const TRUST_SOURCE_SAS_PAIRING: &str = "sas_pairing";
const MAX_PRODUCER_IDENTITY_BYTES: usize = 256;

/// Failures a caller may see through the [`TrustedProducerRegistry`] seam.
///
/// Callers only learn whether an exact fingerprint is currently trusted. They
/// never learn which SQLite table answered, and cannot enumerate trust as a
/// side effect of an admission attempt.
#[derive(Debug, thiserror::Error)]
pub enum TrustedProducerError {
    #[error("trusted producer fingerprint is malformed: {detail}")]
    MalformedFingerprint { detail: String },

    #[error("trusted producer identity is malformed: {detail}")]
    MalformedIdentity { detail: String },

    #[error("trusted producer registry is unavailable: {0}")]
    Unavailable(String),
}

impl From<MediaStoreError> for TrustedProducerError {
    fn from(error: MediaStoreError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

/// Immutable evidence that this PC confirmed a producer key through SAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedProducerKeyReceipt {
    producer_identity: String,
    key_fingerprint: String,
    pairing_evidence_digest: String,
    confirmed_at: String,
}

/// An active RP inline-signature key resolved from PC-owned trust state.
/// The public key is never read from removable media.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedInlinePublicationKey {
    pub producer_identity: String,
    pub key_version: u64,
    pub fingerprint: String,
    pub public_key_hex: String,
}

impl TrustedProducerKeyReceipt {
    #[must_use]
    pub fn producer_identity(&self) -> &str {
        &self.producer_identity
    }

    /// The `sha256:<64 lowercase hex>` identity that must equal the SHA-256 of
    /// the raw Ed25519 public key presented by the card.
    #[must_use]
    pub fn key_fingerprint(&self) -> &str {
        &self.key_fingerprint
    }

    #[must_use]
    pub fn pairing_evidence_digest(&self) -> &str {
        &self.pairing_evidence_digest
    }

    #[must_use]
    pub fn confirmed_at(&self) -> &str {
        &self.confirmed_at
    }
}

/// Read seam used by removable-media admission.
///
/// Deliberately read-only and single-purpose: admission may ask whether one
/// presented fingerprint is currently trusted, and nothing else. Writing trust
/// is a pairing-time action on [`MediaStore`], not something an import path can
/// reach.
pub trait TrustedProducerRegistry: Send + Sync {
    fn resolve_active(
        &self,
        fingerprint: &str,
    ) -> Result<Option<TrustedProducerKeyReceipt>, TrustedProducerError>;

    /// Resolve one exact external device identity and RP key version. Legacy
    /// fingerprint-only registries deliberately return unavailable: accepting
    /// an inline envelope without this binding would make card metadata a
    /// trust authority.
    fn resolve_inline_active(
        &self,
        _external_device_identity: &str,
        _key_version: u64,
    ) -> Result<Option<TrustedInlinePublicationKey>, TrustedProducerError> {
        Err(TrustedProducerError::Unavailable(
            "trusted inline publication-key registry is unavailable".to_string(),
        ))
    }
}

/// Outcome of a pairing-time trust write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmTrustedProducerOutcome {
    /// The exact fingerprint and pairing evidence were already active.
    Unchanged(TrustedProducerKeyReceipt),
    /// A first-time confirmation for this producer.
    Confirmed(TrustedProducerKeyReceipt),
    /// The producer's previous active fingerprint was revoked in the same
    /// transaction and replaced by this one.
    Rotated {
        receipt: TrustedProducerKeyReceipt,
        revoked_fingerprint: String,
    },
}

impl ConfirmTrustedProducerOutcome {
    #[must_use]
    pub fn receipt(&self) -> &TrustedProducerKeyReceipt {
        match self {
            Self::Unchanged(receipt) | Self::Confirmed(receipt) | Self::Rotated { receipt, .. } => {
                receipt
            }
        }
    }
}

/// Canonical digest binding one confirmed SAS transcript.
///
/// The transcript itself (short authentication string, attempt id, and the
/// fingerprint it covered) is never stored. Only this digest is, so an audit
/// can prove which confirmation produced the trust without retaining material
/// that would be useful to an attacker.
#[must_use]
pub fn pairing_evidence_digest(
    producer_identity: &str,
    attempt_id: &str,
    short_authentication_string: &str,
    key_fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ylx-transfer/sas-pairing-evidence-v1\0");
    for field in [
        producer_identity,
        attempt_id,
        short_authentication_string,
        key_fingerprint,
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Validate the `sha256:<64 lowercase hex>` publication-key identity form.
pub fn validate_producer_key_fingerprint(value: &str) -> Result<(), TrustedProducerError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(TrustedProducerError::MalformedFingerprint {
            detail: "expected a sha256: prefix".to_string(),
        });
    };
    if hex.len() != 64 {
        return Err(TrustedProducerError::MalformedFingerprint {
            detail: format!("expected 64 hex digits, got {}", hex.len()),
        });
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TrustedProducerError::MalformedFingerprint {
            detail: "expected lowercase hexadecimal digits".to_string(),
        });
    }
    Ok(())
}

fn validate_producer_identity(value: &str) -> Result<(), TrustedProducerError> {
    if value.is_empty() || value.len() > MAX_PRODUCER_IDENTITY_BYTES {
        return Err(TrustedProducerError::MalformedIdentity {
            detail: format!("length must be 1..={MAX_PRODUCER_IDENTITY_BYTES}"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(TrustedProducerError::MalformedIdentity {
            detail: "control characters are not allowed".to_string(),
        });
    }
    Ok(())
}

fn validate_evidence_digest(value: &str) -> Result<(), TrustedProducerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TrustedProducerError::MalformedFingerprint {
            detail: "pairing evidence digest must be 64 lowercase hex digits".to_string(),
        });
    }
    Ok(())
}

fn receipt_from_row(row: &Row<'_>) -> rusqlite::Result<TrustedProducerKeyReceipt> {
    Ok(TrustedProducerKeyReceipt {
        producer_identity: row.get(0)?,
        key_fingerprint: row.get(1)?,
        pairing_evidence_digest: row.get(2)?,
        confirmed_at: row.get(3)?,
    })
}

impl MediaStore {
    /// Pairing/keyring-owned provisioning entry point for RP inline keys. It
    /// deliberately takes the public key from the authenticated caller, never
    /// from removable media.
    pub fn provision_inline_publication_key(
        &mut self,
        key: &TrustedInlinePublicationKey,
        not_before: &str,
        not_after: Option<&str>,
        registry_revision: u64,
    ) -> Result<(), TrustedProducerError> {
        validate_producer_identity(&key.producer_identity)?;
        validate_producer_key_fingerprint(&key.fingerprint)?;
        if key.key_version == 0
            || key.public_key_hex.len() != 64
            || !key
                .public_key_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || not_before.is_empty()
            || not_after.is_some_and(str::is_empty)
        {
            return Err(TrustedProducerError::Unavailable(
                "invalid inline publication-key provisioning material".to_string(),
            ));
        }
        self.conn.execute(
            "INSERT INTO media_trusted_inline_publication_keys (producer_identity,key_version,key_fingerprint,public_key_hex,not_before,not_after,revoked_at,registry_revision) VALUES (?1,?2,?3,?4,?5,?6,NULL,?7) ON CONFLICT(producer_identity,key_version) DO UPDATE SET key_fingerprint=excluded.key_fingerprint, public_key_hex=excluded.public_key_hex, not_before=excluded.not_before, not_after=excluded.not_after, revoked_at=NULL, registry_revision=excluded.registry_revision",
            rusqlite::params![key.producer_identity, key.key_version, key.fingerprint, key.public_key_hex, not_before, not_after, registry_revision],
        ).map_err(|e| TrustedProducerError::from(MediaStoreError::from(e)))?;
        Ok(())
    }

    pub fn active_inline_publication_key(
        &self,
        producer_identity: &str,
        key_version: u64,
        now: &str,
    ) -> Result<Option<TrustedInlinePublicationKey>, TrustedProducerError> {
        validate_producer_identity(producer_identity)?;
        let mut statement = self.conn.prepare("SELECT producer_identity,key_version,key_fingerprint,public_key_hex FROM media_trusted_inline_publication_keys WHERE producer_identity=?1 AND key_version=?2 AND revoked_at IS NULL AND not_before <= ?3 AND (not_after IS NULL OR not_after > ?3)").map_err(MediaStoreError::from)?;
        statement
            .query_row(
                rusqlite::params![producer_identity, key_version, now],
                |r| {
                    Ok(TrustedInlinePublicationKey {
                        producer_identity: r.get(0)?,
                        key_version: r.get(1)?,
                        fingerprint: r.get(2)?,
                        public_key_hex: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(|e| TrustedProducerError::from(MediaStoreError::from(e)))
    }
    /// Persist a SAS-confirmed producer key.
    ///
    /// Rotation is not an update: the producer's previous active fingerprint
    /// is revoked and the new one inserted inside one transaction, so there is
    /// never a moment where a producer has two active keys or none. A new
    /// manifest can never reach this method — only an operator-confirmed
    /// pairing can.
    pub fn confirm_trusted_producer_key(
        &mut self,
        producer_identity: &str,
        key_fingerprint: &str,
        pairing_evidence_digest: &str,
        confirmed_at: &str,
    ) -> Result<ConfirmTrustedProducerOutcome, TrustedProducerError> {
        validate_producer_identity(producer_identity)?;
        validate_producer_key_fingerprint(key_fingerprint)?;
        validate_evidence_digest(pairing_evidence_digest)?;
        if confirmed_at.is_empty() {
            return Err(TrustedProducerError::MalformedIdentity {
                detail: "confirmation timestamp must not be empty".to_string(),
            });
        }

        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(MediaStoreError::from)?;

        let active: Option<TrustedProducerKeyReceipt> = tx
            .query_row(
                r#"
                SELECT producer_identity, key_fingerprint, pairing_evidence_digest, confirmed_at
                FROM media_trusted_producer_keys
                WHERE producer_identity = ?1 AND revoked_at IS NULL
                "#,
                rusqlite::params![producer_identity],
                receipt_from_row,
            )
            .optional()
            .map_err(MediaStoreError::from)?;

        if let Some(active) = &active {
            if active.key_fingerprint == key_fingerprint
                && active.pairing_evidence_digest == pairing_evidence_digest
            {
                tx.commit().map_err(MediaStoreError::from)?;
                return Ok(ConfirmTrustedProducerOutcome::Unchanged(active.clone()));
            }
        }

        // A fingerprint may only ever describe one producer. Trusting the
        // same key for a second identity would let a rebranded device inherit
        // an unrelated confirmation.
        let foreign_owner: Option<String> = tx
            .query_row(
                r#"
                SELECT producer_identity
                FROM media_trusted_producer_keys
                WHERE key_fingerprint = ?1 AND revoked_at IS NULL AND producer_identity <> ?2
                "#,
                rusqlite::params![key_fingerprint, producer_identity],
                |row| row.get(0),
            )
            .optional()
            .map_err(MediaStoreError::from)?;
        if foreign_owner.is_some() {
            return Err(TrustedProducerError::Unavailable(
                "this publication key is already actively trusted for a different producer"
                    .to_string(),
            ));
        }

        let revoked_fingerprint = match &active {
            Some(active) => {
                tx.execute(
                    r#"
                    UPDATE media_trusted_producer_keys
                    SET revoked_at = ?3
                    WHERE producer_identity = ?1 AND key_fingerprint = ?2 AND revoked_at IS NULL
                    "#,
                    rusqlite::params![producer_identity, active.key_fingerprint, confirmed_at],
                )
                .map_err(MediaStoreError::from)?;
                tx.execute(
                    r#"
                    INSERT INTO media_trusted_producer_audit (
                        producer_identity, key_fingerprint, action,
                        pairing_evidence_digest, recorded_at
                    ) VALUES (?1, ?2, 'revoked', ?3, ?4)
                    "#,
                    rusqlite::params![
                        producer_identity,
                        active.key_fingerprint,
                        active.pairing_evidence_digest,
                        confirmed_at
                    ],
                )
                .map_err(MediaStoreError::from)?;
                Some(active.key_fingerprint.clone())
            }
            None => None,
        };

        // A re-pair of a previously revoked fingerprint re-activates that
        // exact row rather than creating a second history for the same key.
        tx.execute(
            r#"
            INSERT INTO media_trusted_producer_keys (
                producer_identity, key_fingerprint, trust_source,
                pairing_evidence_digest, confirmed_at, revoked_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)
            ON CONFLICT (producer_identity, key_fingerprint) DO UPDATE SET
                trust_source = excluded.trust_source,
                pairing_evidence_digest = excluded.pairing_evidence_digest,
                confirmed_at = excluded.confirmed_at,
                revoked_at = NULL
            "#,
            rusqlite::params![
                producer_identity,
                key_fingerprint,
                TRUST_SOURCE_SAS_PAIRING,
                pairing_evidence_digest,
                confirmed_at
            ],
        )
        .map_err(MediaStoreError::from)?;

        tx.execute(
            r#"
            INSERT INTO media_trusted_producer_audit (
                producer_identity, key_fingerprint, action,
                pairing_evidence_digest, recorded_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            rusqlite::params![
                producer_identity,
                key_fingerprint,
                if revoked_fingerprint.is_some() {
                    "rotated"
                } else {
                    "confirmed"
                },
                pairing_evidence_digest,
                confirmed_at
            ],
        )
        .map_err(MediaStoreError::from)?;

        tx.commit().map_err(MediaStoreError::from)?;

        let receipt = TrustedProducerKeyReceipt {
            producer_identity: producer_identity.to_string(),
            key_fingerprint: key_fingerprint.to_string(),
            pairing_evidence_digest: pairing_evidence_digest.to_string(),
            confirmed_at: confirmed_at.to_string(),
        };
        Ok(match revoked_fingerprint {
            Some(revoked_fingerprint) => ConfirmTrustedProducerOutcome::Rotated {
                receipt,
                revoked_fingerprint,
            },
            None => ConfirmTrustedProducerOutcome::Confirmed(receipt),
        })
    }

    /// Explicitly withdraw trust. Deleting a device from the UI must not call
    /// this; revocation is its own operator action and is always audited.
    pub fn revoke_trusted_producer_key(
        &mut self,
        producer_identity: &str,
        revoked_at: &str,
    ) -> Result<Option<TrustedProducerKeyReceipt>, TrustedProducerError> {
        validate_producer_identity(producer_identity)?;
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(MediaStoreError::from)?;
        let active: Option<TrustedProducerKeyReceipt> = tx
            .query_row(
                r#"
                SELECT producer_identity, key_fingerprint, pairing_evidence_digest, confirmed_at
                FROM media_trusted_producer_keys
                WHERE producer_identity = ?1 AND revoked_at IS NULL
                "#,
                rusqlite::params![producer_identity],
                receipt_from_row,
            )
            .optional()
            .map_err(MediaStoreError::from)?;
        let Some(active) = active else {
            tx.commit().map_err(MediaStoreError::from)?;
            return Ok(None);
        };
        tx.execute(
            r#"
            UPDATE media_trusted_producer_keys
            SET revoked_at = ?3
            WHERE producer_identity = ?1 AND key_fingerprint = ?2 AND revoked_at IS NULL
            "#,
            rusqlite::params![producer_identity, active.key_fingerprint, revoked_at],
        )
        .map_err(MediaStoreError::from)?;
        tx.execute(
            r#"
            INSERT INTO media_trusted_producer_audit (
                producer_identity, key_fingerprint, action,
                pairing_evidence_digest, recorded_at
            ) VALUES (?1, ?2, 'revoked', ?3, ?4)
            "#,
            rusqlite::params![
                producer_identity,
                active.key_fingerprint,
                active.pairing_evidence_digest,
                revoked_at
            ],
        )
        .map_err(MediaStoreError::from)?;
        tx.commit().map_err(MediaStoreError::from)?;
        Ok(Some(active))
    }

    /// Resolve one presented fingerprint to its active confirmation receipt.
    pub fn active_trusted_producer_key(
        &self,
        key_fingerprint: &str,
    ) -> Result<Option<TrustedProducerKeyReceipt>, TrustedProducerError> {
        validate_producer_key_fingerprint(key_fingerprint)?;
        self.conn
            .query_row(
                r#"
                SELECT producer_identity, key_fingerprint, pairing_evidence_digest, confirmed_at
                FROM media_trusted_producer_keys
                WHERE key_fingerprint = ?1 AND revoked_at IS NULL
                "#,
                rusqlite::params![key_fingerprint],
                receipt_from_row,
            )
            .optional()
            .map_err(|error| TrustedProducerError::from(MediaStoreError::from(error)))
    }

    /// Every currently trusted producer, for the pairing/trust UI.
    pub fn list_trusted_producer_keys(
        &self,
    ) -> Result<Vec<TrustedProducerKeyReceipt>, TrustedProducerError> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                SELECT producer_identity, key_fingerprint, pairing_evidence_digest, confirmed_at
                FROM media_trusted_producer_keys
                WHERE revoked_at IS NULL
                ORDER BY producer_identity ASC
                "#,
            )
            .map_err(MediaStoreError::from)?;
        let rows = statement
            .query_map([], receipt_from_row)
            .map_err(MediaStoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(MediaStoreError::from)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(seed: char) -> String {
        format!("sha256:{}", seed.to_string().repeat(64))
    }

    fn store() -> MediaStore {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.keep().join("media.sqlite3");
        MediaStore::open(path).expect("open media store")
    }

    #[test]
    fn a_confirmed_key_resolves_and_a_stranger_does_not() {
        let mut store = store();
        let receipt = store
            .confirm_trusted_producer_key(
                "pi-1",
                &fingerprint('a'),
                &pairing_evidence_digest("pi-1", "attempt-1", "12345", &fingerprint('a')),
                "2026-08-05T00:00:00Z",
            )
            .expect("confirm");
        assert!(matches!(
            receipt,
            ConfirmTrustedProducerOutcome::Confirmed(_)
        ));
        assert!(store
            .active_trusted_producer_key(&fingerprint('a'))
            .expect("resolve")
            .is_some());
        assert!(store
            .active_trusted_producer_key(&fingerprint('b'))
            .expect("resolve")
            .is_none());
    }

    #[test]
    fn rotation_revokes_the_previous_active_fingerprint() {
        let mut store = store();
        store
            .confirm_trusted_producer_key(
                "pi-1",
                &fingerprint('a'),
                &pairing_evidence_digest("pi-1", "attempt-1", "12345", &fingerprint('a')),
                "2026-08-05T00:00:00Z",
            )
            .expect("confirm");
        let rotated = store
            .confirm_trusted_producer_key(
                "pi-1",
                &fingerprint('b'),
                &pairing_evidence_digest("pi-1", "attempt-2", "54321", &fingerprint('b')),
                "2026-08-05T01:00:00Z",
            )
            .expect("rotate");
        assert!(matches!(
            rotated,
            ConfirmTrustedProducerOutcome::Rotated { .. }
        ));
        assert!(store
            .active_trusted_producer_key(&fingerprint('a'))
            .expect("resolve")
            .is_none());
        assert!(store
            .active_trusted_producer_key(&fingerprint('b'))
            .expect("resolve")
            .is_some());
    }

    #[test]
    fn a_malformed_fingerprint_never_reaches_sqlite() {
        let mut store = store();
        assert!(matches!(
            store.confirm_trusted_producer_key(
                "pi-1",
                "not-a-fingerprint",
                &"0".repeat(64),
                "2026-08-05T00:00:00Z",
            ),
            Err(TrustedProducerError::MalformedFingerprint { .. })
        ));
    }

    #[test]
    fn revocation_is_explicit_and_removes_admission() {
        let mut store = store();
        store
            .confirm_trusted_producer_key(
                "pi-1",
                &fingerprint('a'),
                &pairing_evidence_digest("pi-1", "attempt-1", "12345", &fingerprint('a')),
                "2026-08-05T00:00:00Z",
            )
            .expect("confirm");
        let revoked = store
            .revoke_trusted_producer_key("pi-1", "2026-08-05T02:00:00Z")
            .expect("revoke");
        assert!(revoked.is_some());
        assert!(store
            .active_trusted_producer_key(&fingerprint('a'))
            .expect("resolve")
            .is_none());
    }
}
