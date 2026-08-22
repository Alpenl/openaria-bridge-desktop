//! Commit 52/53: **the** publication trust seam.
//!
//! Everything that decides whether a Pi's `GET /sessions/{id}` answer may
//! be believed happens here, once:
//!
//! - the publication **key identity** must be exactly the one this session
//!   is bound to (the SAS-confirmed fingerprint),
//! - the raw public key must hash to that fingerprint,
//! - the detached Ed25519 **signature** must cover the exact received
//!   payload bytes (delegated to a [`PublicationVerifier`], the crypto
//!   backend seam — this crate has no crypto dependency of its own),
//! - the payload's **schema** must be a major version this build knows,
//! - the payload's **session identity** must be the session that was asked
//!   for,
//! - the unsigned envelope's **inventory** must agree with the signed one
//!   entry for entry,
//! - file ids and display **paths must be unique**, and every display path
//!   must be a safe session-relative path,
//! - every **digest** must be exactly 64 lowercase hex characters.
//!
//! The single output is a [`VerifiedPublication`] whose fields are all
//! private and which has **no** public constructor, no `Deserialize`, and
//! no `&mut` accessor. [`PublicationTrust::verify`] is the only thing in
//! the workspace that can produce one, so "this value was verified" is a
//! property of the type rather than a convention every caller has to
//! re-implement.
//!
//! Commit 53 builds on that: a download plan is only obtainable *from* a
//! [`VerifiedPublication`] ([`VerifiedPublication::full_download_plan`] /
//! [`VerifiedPublication::subset_download_plan`]), and the resulting
//! [`VerifiedTransferPlan`] keeps the signed claims and the selected file
//! set in one field-private value. There is no way to hand
//! `JobSpec`-shaped data a signature that does not cover it, because the
//! signed material and the file list are never two independently
//! modifiable arguments.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::device::SessionDetailView;
use crate::domain::{
    DeviceId, FileId, JobFileSpec, JobIdentity, JobSpec, JobSpecError, PublicationMaterial,
    SessionId, PUBLICATION_MANIFEST_KNOWN_MAJOR_VERSIONS,
};
use crate::library::download::{PublicationVerifier, VerifyError};

/// Raw Ed25519 public keys are exactly 32 bytes.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
/// Raw Ed25519 signatures are exactly 64 bytes.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// Every way a publication can fail to be trustworthy.
///
/// Deliberately one flat "rejected" shape carrying a human-readable
/// reason: callers must never branch on *why* a publication was rejected
/// to decide whether to use it anyway.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicationTrustError {
    #[error("publication rejected: {0}")]
    Rejected(String),
}

impl From<VerifyError> for PublicationTrustError {
    fn from(error: VerifyError) -> Self {
        let VerifyError::Rejected(message) = error;
        PublicationTrustError::Rejected(message)
    }
}

impl From<PublicationTrustError> for VerifyError {
    fn from(error: PublicationTrustError) -> Self {
        let PublicationTrustError::Rejected(message) = error;
        VerifyError::Rejected(message)
    }
}

fn rejected(message: impl Into<String>) -> PublicationTrustError {
    PublicationTrustError::Rejected(message.into())
}

/// Parse an RP-YLX JSON document without accepting JSON's duplicate-key or
/// non-finite-number extensions.  This is intentionally performed before
/// serde_json builds a map, since a map would otherwise silently retain the
/// final value of a duplicate key.
pub fn parse_strict_json(raw: &[u8]) -> Result<Value, PublicationTrustError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| rejected("publication manifest is not valid UTF-8"))?;
    validate_surrogate_escapes(text)?;
    StrictJsonAudit::new(text).audit()?;
    serde_json::from_str(text)
        .map_err(|error| rejected(format!("publication manifest is not valid JSON: {error}")))
}

fn validate_surrogate_escapes(text: &str) -> Result<(), PublicationTrustError> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if bytes[i] != b'\\' || bytes[i + 1] != b'u' {
            i += 1;
            continue;
        }
        let parse = |at: usize| -> Option<u16> {
            std::str::from_utf8(bytes.get(at..at + 4)?)
                .ok()
                .and_then(|v| u16::from_str_radix(v, 16).ok())
        };
        let Some(unit) = parse(i + 2) else {
            return Err(rejected("invalid strict JSON unicode escape"));
        };
        if (0xd800..=0xdbff).contains(&unit) {
            let Some(low) = (bytes.get(i + 6) == Some(&b'\\') && bytes.get(i + 7) == Some(&b'u'))
                .then(|| parse(i + 8))
                .flatten()
            else {
                return Err(rejected("invalid strict JSON: isolated Unicode surrogate"));
            };
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(rejected("invalid strict JSON: isolated Unicode surrogate"));
            }
            i += 12;
        } else if (0xdc00..=0xdfff).contains(&unit) {
            return Err(rejected("invalid strict JSON: isolated Unicode surrogate"));
        } else {
            i += 6;
        }
    }
    Ok(())
}

/// RP-YLX v1 signature bytes: compact, recursively key-sorted ASCII JSON,
/// omitting only the top-level `publication_signature` field.
pub fn canonicalize_rp_manifest(manifest: &Value) -> Result<Vec<u8>, PublicationTrustError> {
    let object = manifest
        .as_object()
        .ok_or_else(|| rejected("publication manifest must be a JSON object"))?;
    if !object.contains_key("publication_signature") {
        return Err(rejected(
            "publication manifest is missing publication_signature",
        ));
    }
    let mut copy = object.clone();
    copy.remove("publication_signature");
    let mut output = String::new();
    write_canonical_json(&Value::Object(copy), &mut output)?;
    Ok(output.into_bytes())
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), PublicationTrustError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => write_ascii_json_string(value, output),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_ascii_json_string(key, output);
                output.push(':');
                write_canonical_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn write_ascii_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if u32::from(character) <= 0x1f => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            character if character.is_ascii() => output.push(character),
            character if u32::from(character) <= 0xffff => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            character => {
                use std::fmt::Write as _;
                let scalar = u32::from(character) - 0x1_0000;
                let high = 0xd800 + (scalar >> 10);
                let low = 0xdc00 + (scalar & 0x3ff);
                let _ = write!(output, "\\u{high:04x}\\u{low:04x}");
            }
        }
    }
    output.push('"');
}

/// Small lexical audit whose only job is preserving strict JSON semantics
/// before serde_json performs its convenient map conversion.
struct StrictJsonAudit<'a> {
    input: &'a [u8],
    offset: usize,
}
impl<'a> StrictJsonAudit<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            offset: 0,
        }
    }
    fn audit(mut self) -> Result<(), PublicationTrustError> {
        self.ws();
        self.value()?;
        self.ws();
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(rejected("invalid strict JSON trailing data"))
        }
    }
    fn ws(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }
    fn value(&mut self) -> Result<(), PublicationTrustError> {
        self.ws();
        match self.input.get(self.offset) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'\"') => self.string().map(|_| ()),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(rejected("invalid strict JSON value")),
        }
    }
    fn literal(&mut self, expected: &[u8]) -> Result<(), PublicationTrustError> {
        if self.input.get(self.offset..self.offset + expected.len()) == Some(expected) {
            self.offset += expected.len();
            Ok(())
        } else {
            Err(rejected("invalid strict JSON literal"))
        }
    }
    fn object(&mut self) -> Result<(), PublicationTrustError> {
        self.offset += 1;
        self.ws();
        let mut keys = HashSet::new();
        if self.input.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Ok(());
        }
        loop {
            self.ws();
            let key = self.string()?;
            if !keys.insert(key) {
                return Err(rejected("invalid strict JSON: duplicate JSON object key"));
            }
            self.ws();
            if self.take(b':').is_none() {
                return Err(rejected("invalid strict JSON object"));
            }
            self.value()?;
            self.ws();
            if self.take(b'}').is_some() {
                return Ok(());
            }
            if self.take(b',').is_none() {
                return Err(rejected("invalid strict JSON object"));
            }
        }
    }
    fn array(&mut self) -> Result<(), PublicationTrustError> {
        self.offset += 1;
        self.ws();
        if self.take(b']').is_some() {
            return Ok(());
        }
        loop {
            self.value()?;
            self.ws();
            if self.take(b']').is_some() {
                return Ok(());
            }
            if self.take(b',').is_none() {
                return Err(rejected("invalid strict JSON array"));
            }
        }
    }
    fn take(&mut self, byte: u8) -> Option<()> {
        (self.input.get(self.offset) == Some(&byte)).then(|| self.offset += 1)
    }
    fn string(&mut self) -> Result<String, PublicationTrustError> {
        if self.take(b'\"').is_none() {
            return Err(rejected("invalid strict JSON string"));
        }
        let start = self.offset - 1;
        let mut escaped = false;
        while let Some(&byte) = self.input.get(self.offset) {
            self.offset += 1;
            if escaped {
                if byte == b'u' {
                    for _ in 0..4 {
                        if !self
                            .input
                            .get(self.offset)
                            .is_some_and(u8::is_ascii_hexdigit)
                        {
                            return Err(rejected("invalid strict JSON unicode escape"));
                        }
                        self.offset += 1;
                    }
                } else if !matches!(
                    byte,
                    b'\"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                ) {
                    return Err(rejected("invalid strict JSON escape"));
                }
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
            } else if byte == b'\"' {
                let raw = std::str::from_utf8(&self.input[start..self.offset])
                    .map_err(|_| rejected("invalid strict JSON UTF-8"))?;
                let decoded: String = serde_json::from_str(raw)
                    .map_err(|_| rejected("invalid strict JSON string"))?;
                if decoded
                    .chars()
                    .any(|c| (0xd800..=0xdfff).contains(&u32::from(c)))
                {
                    return Err(rejected("invalid strict JSON: isolated Unicode surrogate"));
                }
                return Ok(decoded);
            } else if byte < 0x20 {
                return Err(rejected("invalid strict JSON control character"));
            }
        }
        Err(rejected("invalid strict JSON unterminated string"))
    }
    fn number(&mut self) -> Result<(), PublicationTrustError> {
        let start = self.offset;
        let _ = self.take(b'-');
        if self.take(b'0').is_none() {
            if !self
                .input
                .get(self.offset)
                .is_some_and(|b| b'1' <= *b && *b <= b'9')
            {
                return Err(rejected("invalid strict JSON number"));
            }
            while self.input.get(self.offset).is_some_and(u8::is_ascii_digit) {
                self.offset += 1;
            }
        }
        if self.take(b'.').is_some() {
            let digits = self.offset;
            while self.input.get(self.offset).is_some_and(u8::is_ascii_digit) {
                self.offset += 1;
            }
            if digits == self.offset {
                return Err(rejected("invalid strict JSON number"));
            }
        }
        if self
            .input
            .get(self.offset)
            .is_some_and(|b| matches!(*b, b'e' | b'E'))
        {
            self.offset += 1;
            if self
                .input
                .get(self.offset)
                .is_some_and(|b| matches!(*b, b'+' | b'-'))
            {
                self.offset += 1;
            }
            let digits = self.offset;
            while self.input.get(self.offset).is_some_and(u8::is_ascii_digit) {
                self.offset += 1;
            }
            if digits == self.offset {
                return Err(rejected("invalid strict JSON number"));
            }
        }
        let raw = std::str::from_utf8(&self.input[start..self.offset]).unwrap_or_default();
        if raw.parse::<f64>().ok().is_none_or(|n| !n.is_finite()) {
            return Err(rejected("invalid strict JSON non-finite number"));
        }
        Ok(())
    }
}

// =====================================================================
// Untrusted input
// =====================================================================

/// One `files[]` entry exactly as it arrived on the wire. **Untrusted.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationFileClaim {
    pub id: String,
    pub display_path: String,
    pub role: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub media_type: String,
}

/// A whole `GET /sessions/{id}` response as it arrived on the wire.
/// **Untrusted**: every field here is attacker-controlled until
/// [`PublicationTrust::verify`] has accepted it.
///
/// Public fields on purpose — this is the *input* side of the seam and an
/// adapter has to be able to fill it in from its own wire DTO. The output
/// side ([`VerifiedPublication`]) is the field-private one.
#[derive(Debug, Clone)]
pub struct PublicationEnvelope {
    pub session_id: String,
    pub revision: String,
    pub captured_at: String,
    pub published_at: String,
    pub duration_seconds: f64,
    pub total_bytes: u64,
    pub video_bytes: u64,
    pub file_count: u64,
    pub files: Vec<PublicationFileClaim>,
    /// The exact UTF-8 canonical JSON text the signature covers. Never
    /// reparsed-and-reserialized before verification: any byte-level
    /// mutation must invalidate the signature.
    pub publication_payload: String,
    /// Lowercase hex, 128 characters.
    pub publication_signature_hex: String,
    /// Lowercase hex, 64 characters.
    pub publication_public_key_hex: String,
    /// `sha256:<64 lowercase hex>` as claimed by the envelope.
    pub publication_key_fingerprint: String,
}

impl PublicationEnvelope {
    /// Convert the core's authenticated session-detail view into the
    /// untrusted envelope consumed by [`PublicationTrust`]. The bytes are
    /// copied exactly; no parse/re-serialize step is performed before the
    /// detached-signature verifier sees them.
    pub fn from_session_detail(detail: &SessionDetailView) -> Result<Self, PublicationTrustError> {
        let publication_payload = String::from_utf8(detail.publication_payload.clone())
            .map_err(|_| rejected("publication payload is not valid UTF-8"))?;
        Ok(Self {
            session_id: detail.session_id.clone(),
            revision: detail.revision.clone(),
            captured_at: detail.captured_at.clone(),
            published_at: detail.published_at.clone(),
            duration_seconds: detail.duration_seconds,
            total_bytes: detail.total_bytes,
            video_bytes: detail.video_bytes,
            file_count: detail.file_count,
            files: detail
                .files
                .iter()
                .map(|file| PublicationFileClaim {
                    id: file.id.clone(),
                    display_path: file.display_path.clone(),
                    role: file.role.clone(),
                    size_bytes: file.size_bytes,
                    sha256: file.sha256.clone(),
                    media_type: file.media_type.clone(),
                })
                .collect(),
            publication_payload,
            publication_signature_hex: encode_lower_hex(&detail.publication_signature),
            publication_public_key_hex: encode_lower_hex(&detail.publication_public_key),
            publication_key_fingerprint: detail.publication_key_fingerprint.clone(),
        })
    }
}

impl TryFrom<&SessionDetailView> for PublicationEnvelope {
    type Error = PublicationTrustError;

    fn try_from(detail: &SessionDetailView) -> Result<Self, Self::Error> {
        Self::from_session_detail(detail)
    }
}

// =====================================================================
// Verified output
// =====================================================================

/// One file of a [`VerifiedPublication`]'s signed inventory.
///
/// Fields are private: a caller cannot take a verified entry and swap its
/// `sha256`, `size_bytes` or `display_path` afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFile {
    file_id: FileId,
    display_path: String,
    role: String,
    size_bytes: u64,
    sha256: String,
    media_type: String,
}

impl VerifiedFile {
    #[must_use]
    pub fn file_id(&self) -> &FileId {
        &self.file_id
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.file_id.as_str()
    }

    /// The signed, schema-validated session-relative path. Guaranteed to
    /// contain no `..`, no leading `/`, no backslash, and to be unique
    /// within the publication.
    #[must_use]
    pub fn display_path(&self) -> &str {
        &self.display_path
    }

    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }

    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Exactly 64 lowercase hex characters.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

/// A publication that has passed **every** check in this module.
///
/// There is no public constructor, no `Deserialize`, no public field and
/// no mutating accessor: the only way to obtain one is
/// [`PublicationTrust::verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedPublication {
    session_id: SessionId,
    revision: String,
    captured_at: String,
    published_at: String,
    duration_seconds: f64,
    total_bytes: u64,
    video_bytes: u64,
    key_fingerprint: String,
    payload: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    files: Vec<VerifiedFile>,
}

impl VerifiedPublication {
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub fn session_id_str(&self) -> &str {
        self.session_id.as_str()
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn captured_at(&self) -> &str {
        &self.captured_at
    }

    #[must_use]
    pub fn published_at(&self) -> &str {
        &self.published_at
    }

    #[must_use]
    pub fn duration_seconds(&self) -> f64 {
        self.duration_seconds
    }

    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub fn video_bytes(&self) -> u64 {
        self.video_bytes
    }

    #[must_use]
    pub fn file_count(&self) -> u64 {
        self.files.len() as u64
    }

    /// The SAS-confirmed publication key identity this publication was
    /// verified against (`sha256:<64 lowercase hex>`).
    #[must_use]
    pub fn key_fingerprint(&self) -> &str {
        &self.key_fingerprint
    }

    /// Exact signed bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Raw 64-byte Ed25519 signature.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Raw 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The complete signed inventory, in manifest order.
    #[must_use]
    pub fn files(&self) -> &[VerifiedFile] {
        &self.files
    }

    // -----------------------------------------------------------------
    // Commit 53: plans
    // -----------------------------------------------------------------

    /// **Full download rule:** every file of the signed inventory, in
    /// manifest order, marked as a full-session transfer. There is no way
    /// to build a "full" plan that omits a signed file.
    #[must_use]
    pub fn full_download_plan(self) -> VerifiedTransferPlan {
        let requested = (0..self.files.len()).collect();
        VerifiedTransferPlan {
            publication: self,
            requested,
            full_session: true,
        }
    }

    /// **Legitimate subset rule:** `requested` must be non-empty, must
    /// contain no duplicates, and every id must appear in the signed
    /// inventory. Files are ordered as requested. A subset that happens to
    /// name every inventory file *is* a full-session transfer and is
    /// recorded as one — "full" is a property of the selection, never an
    /// independently settable flag.
    pub fn subset_download_plan(
        self,
        requested: &[FileId],
    ) -> Result<VerifiedTransferPlan, PublicationTrustError> {
        if requested.is_empty() {
            return Err(rejected("a download plan must request at least one file"));
        }
        let mut indices = Vec::with_capacity(requested.len());
        for id in requested {
            let Some(position) = self.files.iter().position(|file| file.file_id() == id) else {
                return Err(rejected(format!(
                    "requested file {:?} is not part of the signed session inventory",
                    id.as_str()
                )));
            };
            if indices.contains(&position) {
                return Err(rejected(format!(
                    "requested file {:?} appears more than once in the download plan",
                    id.as_str()
                )));
            }
            indices.push(position);
        }
        let full_session = indices.len() == self.files.len();
        Ok(VerifiedTransferPlan {
            publication: self,
            requested: indices,
            full_session,
        })
    }
}

/// A signed publication **and** the exact set of files a transfer will
/// download, bound together.
///
/// Field-private with no public constructor: the only entry points are
/// [`VerifiedPublication::full_download_plan`] and
/// [`VerifiedPublication::subset_download_plan`], and the selection is
/// stored as indices into the signed inventory rather than as a second
/// copy of the file entries. A requested file therefore *cannot* carry a
/// size or digest that differs from the signed one, and the signed claims
/// cannot be swapped for a different file list after the fact.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedTransferPlan {
    publication: VerifiedPublication,
    requested: Vec<usize>,
    full_session: bool,
}

impl VerifiedTransferPlan {
    #[must_use]
    pub fn publication(&self) -> &VerifiedPublication {
        &self.publication
    }

    /// The files this plan actually transfers, in request order.
    pub fn files(&self) -> impl Iterator<Item = &VerifiedFile> {
        self.requested.iter().map(|i| &self.publication.files[*i])
    }

    #[must_use]
    pub fn file_count(&self) -> usize {
        self.requested.len()
    }

    #[must_use]
    pub fn is_full_session(&self) -> bool {
        self.full_session
    }

    /// The durable [`JobSpec`] this plan represents.
    ///
    /// `JobSpec::new` re-checks the same invariants from its own side, so
    /// the two constructions cannot drift apart silently.
    pub fn into_job_spec(
        self,
        device_id: DeviceId,
        date_label: impl Into<String>,
    ) -> Result<JobSpec, JobSpecError> {
        let identity = JobIdentity::new(
            device_id,
            self.publication.session_id.clone(),
            self.publication.revision.clone(),
        )?;
        let material = PublicationMaterial::new(
            self.publication.revision.clone(),
            self.publication.payload.clone(),
            self.publication.signature.clone(),
            self.publication.public_key.clone(),
        )?;
        let session_files = self
            .publication
            .files
            .iter()
            .map(|file| {
                JobFileSpec::new(
                    file.file_id.clone(),
                    file.display_path.clone(),
                    file.size_bytes,
                    file.sha256.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let requested: Vec<FileId> = self
            .requested
            .iter()
            .map(|i| self.publication.files[*i].file_id.clone())
            .collect();
        JobSpec::new(
            identity,
            material,
            session_files,
            &requested,
            self.full_session,
            date_label,
        )
    }
}

// =====================================================================
// PublicationTrust
// =====================================================================

/// The one verifier. Holds only the crypto backend seam.
pub struct PublicationTrust<'a> {
    verifier: &'a dyn PublicationVerifier,
}

impl<'a> PublicationTrust<'a> {
    #[must_use]
    pub fn new(verifier: &'a dyn PublicationVerifier) -> Self {
        PublicationTrust { verifier }
    }

    /// Verify one session-detail envelope against the session's bound
    /// publication key identity.
    ///
    /// `expected_key_fingerprint` is the identity the pairing SAS
    /// confirmation covered (or, for a legacy transcript-less pairing, the
    /// authenticated `GET /device` identity). The envelope is *not* a
    /// trust anchor and can never authenticate itself.
    pub fn verify(
        &self,
        envelope: &PublicationEnvelope,
        requested_session_id: &str,
        expected_key_fingerprint: &str,
    ) -> Result<VerifiedPublication, PublicationTrustError> {
        // 1. Key identity.
        ensure_publication_key_identity_matches(
            expected_key_fingerprint,
            &envelope.publication_key_fingerprint,
        )?;

        // 2. Session identity of the request itself.
        validate_opaque_id("requested session_id", requested_session_id)?;
        if envelope.session_id != requested_session_id {
            return Err(rejected(
                "session detail response does not match the requested session_id",
            ));
        }

        // 3. Key material, and the fingerprint it really hashes to.
        let public_key = decode_lower_hex_exact(
            "publication_public_key",
            &envelope.publication_public_key_hex,
            ED25519_PUBLIC_KEY_LENGTH,
        )?;
        let signature = decode_lower_hex_exact(
            "publication_signature",
            &envelope.publication_signature_hex,
            ED25519_SIGNATURE_LENGTH,
        )?;
        let computed_fingerprint = format!("sha256:{:x}", Sha256::digest(&public_key));
        if computed_fingerprint != envelope.publication_key_fingerprint {
            return Err(rejected(
                "publication public key hash does not match its fingerprint",
            ));
        }

        // 4. Signature over the exact received bytes.
        let payload_bytes = envelope.publication_payload.as_bytes();
        self.verifier
            .verify(payload_bytes, &signature, &public_key)?;

        // 5. Schema.
        let payload_value = parse_strict_json(payload_bytes)?;
        let payload_object = payload_value
            .as_object()
            .ok_or_else(|| rejected("publication payload must be a JSON object"))?;
        if payload_object.contains_key("publication_signature") {
            return Err(rejected(
                "publication payload must exclude publication_signature",
            ));
        }
        let payload: SignedPublicationPayload = serde_json::from_value(payload_value.clone())
            .map_err(|error| rejected(format!("publication payload schema is invalid: {error}")))?;

        if !PUBLICATION_MANIFEST_KNOWN_MAJOR_VERSIONS.contains(&payload.schema_version) {
            return Err(rejected(format!(
                "unsupported publication schema_version {}",
                payload.schema_version
            )));
        }
        // RP derives revision from precisely these content fields, not from
        // the signature envelope or publication timestamp. Verify it before
        // treating the manifest inventory as a stable source identity.
        let content = payload_object_for_revision(&payload_value)?;
        let mut canonical = String::new();
        write_canonical_json(&content, &mut canonical)?;
        let expected_revision = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
        if payload.revision != expected_revision {
            return Err(rejected(
                "publication revision does not match RP canonical content fields",
            ));
        }
        if !payload.integrity_ok {
            return Err(rejected("publication payload reports integrity_ok=false"));
        }

        // 6. Signed session identity and scalars.
        validate_opaque_id("signed session_id", &payload.session_id)?;
        validate_revision(&payload.revision)?;
        let captured_at = parse_rfc3339_seconds("signed captured_at", &payload.captured_at)?;
        let published_at = parse_rfc3339_seconds("signed published_at", &payload.published_at)?;
        if published_at < captured_at {
            return Err(rejected(
                "signed published_at must not be earlier than signed captured_at",
            ));
        }
        if !payload.duration_seconds.is_finite() || payload.duration_seconds < 0.0 {
            return Err(rejected(
                "signed duration_seconds must be a finite non-negative number",
            ));
        }
        if payload.session_id != envelope.session_id
            || payload.revision != envelope.revision
            || payload.captured_at != envelope.captured_at
            || payload.published_at != envelope.published_at
            || payload.duration_seconds != envelope.duration_seconds
            || payload.total_bytes != envelope.total_bytes
            || payload.video_bytes != envelope.video_bytes
        {
            return Err(rejected(
                "session detail scalar fields do not match the signed publication payload",
            ));
        }

        // 7. Inventory: the unsigned echo must equal the signed list.
        if payload.files.len() as u64 != envelope.file_count
            || payload.files.is_empty()
            || envelope.files.len() as u64 != envelope.file_count
            || payload.files.len() != envelope.files.len()
            || !payload
                .files
                .iter()
                .zip(&envelope.files)
                .all(|(signed, wire)| file_entry_matches(signed, wire))
        {
            return Err(rejected(
                "session detail file inventory does not match the signed publication payload",
            ));
        }

        // 8. Per-file schema, uniqueness, digest format, aggregates.
        let mut file_ids = HashSet::with_capacity(payload.files.len());
        let mut display_paths = HashSet::with_capacity(payload.files.len());
        let mut total_bytes = 0_u64;
        let mut video_bytes = 0_u64;
        let mut files = Vec::with_capacity(payload.files.len());
        for file in &payload.files {
            validate_opaque_id("signed file id", &file.id)?;
            validate_display_path(&file.display_path)?;
            validate_media_type(&file.media_type)?;
            if !file_ids.insert(file.id.as_str()) {
                return Err(rejected(
                    "signed publication payload contains duplicate file ids",
                ));
            }
            if !display_paths.insert(file.display_path.as_str()) {
                return Err(rejected(
                    "signed publication payload contains duplicate file display_paths",
                ));
            }
            if file.sha256.len() != 64 || !is_lower_hex(&file.sha256) {
                return Err(rejected(
                    "signed file sha256 must contain 64 lowercase hex characters",
                ));
            }
            if !is_known_v1_role(&file.role) {
                return Err(rejected("signed file role is not supported by schema v1"));
            }
            total_bytes = total_bytes
                .checked_add(file.size_bytes)
                .ok_or_else(|| rejected("signed file sizes overflow total_bytes"))?;
            if is_video_role(&file.role) {
                video_bytes = video_bytes
                    .checked_add(file.size_bytes)
                    .ok_or_else(|| rejected("signed video sizes overflow video_bytes"))?;
            }
            files.push(VerifiedFile {
                file_id: FileId(file.id.clone()),
                display_path: file.display_path.clone(),
                role: file.role.clone(),
                size_bytes: file.size_bytes,
                sha256: file.sha256.clone(),
                media_type: file.media_type.clone(),
            });
        }
        if total_bytes != payload.total_bytes || video_bytes != payload.video_bytes {
            return Err(rejected(
                "signed aggregate byte counts do not match the signed file inventory",
            ));
        }

        Ok(VerifiedPublication {
            session_id: SessionId(payload.session_id),
            revision: payload.revision,
            captured_at: payload.captured_at,
            published_at: payload.published_at,
            duration_seconds: payload.duration_seconds,
            total_bytes: payload.total_bytes,
            video_bytes: payload.video_bytes,
            key_fingerprint: computed_fingerprint,
            payload: payload_bytes.to_vec(),
            signature,
            public_key,
            files,
        })
    }
}

fn payload_object_for_revision(value: &Value) -> Result<Value, PublicationTrustError> {
    const FIELDS: &[&str] = &[
        "schema_version",
        "session_id",
        "captured_at",
        "duration_seconds",
        "total_bytes",
        "video_bytes",
        "integrity_ok",
        "files",
    ];
    let object = value
        .as_object()
        .ok_or_else(|| rejected("publication payload must be a JSON object"))?;
    let mut content = serde_json::Map::new();
    for field in FIELDS {
        content.insert(
            (*field).to_string(),
            object.get(*field).cloned().ok_or_else(|| {
                rejected("publication payload is missing RP revision content field")
            })?,
        );
    }
    Ok(Value::Object(content))
}

// =====================================================================
// The signed payload's own schema
// =====================================================================

#[derive(Debug, Deserialize)]
struct SignedPublicationPayload {
    schema_version: u32,
    session_id: String,
    revision: String,
    captured_at: String,
    published_at: String,
    duration_seconds: f64,
    total_bytes: u64,
    video_bytes: u64,
    integrity_ok: bool,
    files: Vec<SignedFileEntry>,
}

#[derive(Debug, Deserialize)]
struct SignedFileEntry {
    id: String,
    display_path: String,
    role: String,
    size_bytes: u64,
    sha256: String,
    media_type: String,
}

fn file_entry_matches(signed: &SignedFileEntry, wire: &PublicationFileClaim) -> bool {
    signed.id == wire.id
        && signed.display_path == wire.display_path
        && signed.role == wire.role
        && signed.size_bytes == wire.size_bytes
        && signed.sha256 == wire.sha256
        && signed.media_type == wire.media_type
}

fn is_known_v1_role(role: &str) -> bool {
    matches!(
        role,
        "video_left" | "video_right" | "video_mono" | "video_stereo" | "imu" | "metadata" | "other"
    )
}

fn is_video_role(role: &str) -> bool {
    matches!(
        role,
        "video_left" | "video_right" | "video_mono" | "video_stereo"
    )
}

// =====================================================================
// Shared format validators
// =====================================================================

fn is_lower_hex(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn decode_lower_hex_exact(
    field: &str,
    value: &str,
    expected_bytes: usize,
) -> Result<Vec<u8>, PublicationTrustError> {
    if value.len() != expected_bytes * 2 || !is_lower_hex(value) {
        return Err(rejected(format!(
            "{field} must be exactly {} lowercase hex characters",
            expected_bytes * 2
        )));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(expected_bytes);
    for index in (0..bytes.len()).step_by(2) {
        let nibble = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            _ => byte - b'a' + 10,
        };
        decoded.push((nibble(bytes[index]) << 4) | nibble(bytes[index + 1]));
    }
    Ok(decoded)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Validate the wire form used for publication-key identities.
pub fn validate_publication_key_fingerprint(value: &str) -> Result<(), PublicationTrustError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(rejected(
            "publication key fingerprint must start with sha256:",
        ));
    };
    if hex.len() != 64 || !is_lower_hex(hex) {
        return Err(rejected(
            "publication key fingerprint must contain 64 lowercase hex characters",
        ));
    }
    Ok(())
}

/// Fail closed unless the publication key identity a response presents is
/// *exactly* the one this session is bound to.
///
/// Accepting a rotated key requires a fresh SAS confirmation, i.e.
/// re-pairing — a validly-signed publication under a new key is still
/// rejected here.
pub fn ensure_publication_key_identity_matches(
    expected: &str,
    observed: &str,
) -> Result<(), PublicationTrustError> {
    validate_publication_key_fingerprint(expected)?;
    validate_publication_key_fingerprint(observed)?;
    if expected != observed {
        return Err(rejected(
            "session publication key fingerprint does not match the SAS-confirmed authenticated /device identity",
        ));
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<(), PublicationTrustError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(rejected("publication revision must start with sha256:"));
    };
    if hex.len() != 64 || !is_lower_hex(hex) {
        return Err(rejected(
            "publication revision must contain 64 lowercase hex characters",
        ));
    }
    Ok(())
}

fn validate_opaque_id(field: &str, value: &str) -> Result<(), PublicationTrustError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
    {
        return Err(rejected(format!(
            "{field} must match [A-Za-z0-9_-]{{1,128}}"
        )));
    }
    Ok(())
}

fn validate_display_path(value: &str) -> Result<(), PublicationTrustError> {
    let bytes = value.as_bytes();
    let valid_first = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    let valid_rest = bytes
        .iter()
        .skip(1)
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'/' | b'-'));
    if bytes.len() > 4096
        || !valid_first
        || !valid_rest
        || bytes.windows(2).any(|pair| pair == b"..")
    {
        return Err(rejected(
            "signed file display_path does not satisfy the schema v1 relative-path constraints",
        ));
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<(), PublicationTrustError> {
    if value.is_empty() || value.chars().count() > 255 {
        return Err(rejected(
            "signed file media_type must contain between 1 and 255 characters",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Strict RFC 3339 parsing
// ---------------------------------------------------------------------
//
// This crate deliberately has no date-time dependency (see
// `domain`'s module doc comment). Publication timestamps only need two
// things: rejection of anything that is not a real RFC 3339 instant, and a
// total order so `published_at >= captured_at` is checkable. Both are done
// here by converting to seconds since the Unix epoch.

fn parse_rfc3339_seconds(field: &str, value: &str) -> Result<i64, PublicationTrustError> {
    parse_rfc3339_inner(value).ok_or_else(|| {
        rejected(format!(
            "{field} must be a valid RFC3339 timestamp, got {value:?}"
        ))
    })
}

fn parse_rfc3339_inner(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !value.is_ascii() {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = value.get(range)?;
        if slice.bytes().all(|b| b.is_ascii_digit()) {
            slice.parse::<i64>().ok()
        } else {
            None
        }
    };
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year = digits(0..4)?;
    let month = digits(5..7)?;
    let day = digits(8..10)?;
    let hour = digits(11..13)?;
    let minute = digits(14..16)?;
    let second = digits(17..19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || day > days_in_month(year, month) {
        return None;
    }
    // Leap seconds (`:60`) are legal in RFC 3339.
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let mut rest = &value[19..];
    if let Some(stripped) = rest.strip_prefix('.') {
        let fraction_len = stripped.bytes().take_while(u8::is_ascii_digit).count();
        if fraction_len == 0 {
            return None;
        }
        rest = &stripped[fraction_len..];
    }

    let offset_seconds = match rest.as_bytes() {
        [b'Z'] | [b'z'] => 0,
        [sign @ (b'+' | b'-'), ..] if rest.len() == 6 => {
            let bytes = rest.as_bytes();
            if bytes[3] != b':' {
                return None;
            }
            let offset_hour = rest.get(1..3)?.parse::<i64>().ok()?;
            let offset_minute = rest.get(4..6)?.parse::<i64>().ok()?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let magnitude = offset_hour * 3600 + offset_minute * 60;
            if *sign == b'-' {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return None,
    };

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Howard Hinnant's `days_from_civil`: days since 1970-01-01 for a proleptic
/// Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptAll;
    impl PublicationVerifier for AcceptAll {
        fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), VerifyError> {
            Ok(())
        }
    }

    struct RejectAll;
    impl PublicationVerifier for RejectAll {
        fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<(), VerifyError> {
            Err(VerifyError::Rejected(
                "invalid Ed25519 publication signature".to_string(),
            ))
        }
    }

    /// The 32-byte key whose hex is "00"*32 -- its fingerprint is fixed, so
    /// fixtures can bind to a real hash rather than a made-up one.
    fn test_public_key_hex() -> String {
        "00".repeat(ED25519_PUBLIC_KEY_LENGTH)
    }

    fn test_fingerprint() -> String {
        format!(
            "sha256:{:x}",
            Sha256::digest(vec![0_u8; ED25519_PUBLIC_KEY_LENGTH])
        )
    }

    fn signed_payload(files: &serde_json::Value) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "schema_version": 1,
            "session_id": "sess-1",
            "revision": "",
            "captured_at": "2026-08-01T00:00:00Z",
            "published_at": "2026-08-01T00:01:00Z",
            "duration_seconds": 12.5,
            "total_bytes": 120,
            "video_bytes": 100,
            "integrity_ok": true,
            "files": files.clone(),
        });
        refresh_revision(&mut payload);
        payload
    }

    fn refresh_revision(payload: &mut serde_json::Value) {
        let content = payload_object_for_revision(payload).unwrap();
        let mut canonical = String::new();
        write_canonical_json(&content, &mut canonical).unwrap();
        payload["revision"] =
            serde_json::json!(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())));
    }

    fn default_files() -> serde_json::Value {
        serde_json::json!([
            {
                "id": "f-0001",
                "display_path": "video/left_00000.mp4",
                "role": "video_left",
                "size_bytes": 100,
                "sha256": "b".repeat(64),
                "media_type": "video/mp4",
            },
            {
                "id": "f-0002",
                "display_path": "imu/imu_00000.csv",
                "role": "imu",
                "size_bytes": 20,
                "sha256": "c".repeat(64),
                "media_type": "text/csv",
            },
        ])
    }

    fn envelope_from(payload: &serde_json::Value) -> PublicationEnvelope {
        let files = payload["files"]
            .as_array()
            .expect("fixture files")
            .iter()
            .map(|file| PublicationFileClaim {
                id: file["id"].as_str().unwrap().to_string(),
                display_path: file["display_path"].as_str().unwrap().to_string(),
                role: file["role"].as_str().unwrap().to_string(),
                size_bytes: file["size_bytes"].as_u64().unwrap(),
                sha256: file["sha256"].as_str().unwrap().to_string(),
                media_type: file["media_type"].as_str().unwrap().to_string(),
            })
            .collect::<Vec<_>>();
        PublicationEnvelope {
            session_id: payload["session_id"].as_str().unwrap().to_string(),
            revision: payload["revision"].as_str().unwrap().to_string(),
            captured_at: payload["captured_at"].as_str().unwrap().to_string(),
            published_at: payload["published_at"].as_str().unwrap().to_string(),
            duration_seconds: payload["duration_seconds"].as_f64().unwrap(),
            total_bytes: payload["total_bytes"].as_u64().unwrap(),
            video_bytes: payload["video_bytes"].as_u64().unwrap(),
            file_count: files.len() as u64,
            files,
            publication_payload: payload.to_string(),
            publication_signature_hex: "ab".repeat(ED25519_SIGNATURE_LENGTH),
            publication_public_key_hex: test_public_key_hex(),
            publication_key_fingerprint: test_fingerprint(),
        }
    }

    fn valid_envelope() -> PublicationEnvelope {
        envelope_from(&signed_payload(&default_files()))
    }

    fn verify(
        envelope: &PublicationEnvelope,
    ) -> Result<VerifiedPublication, PublicationTrustError> {
        PublicationTrust::new(&AcceptAll).verify(envelope, "sess-1", &test_fingerprint())
    }

    fn error_of(envelope: &PublicationEnvelope) -> String {
        match verify(envelope) {
            Ok(_) => panic!("expected rejection"),
            Err(PublicationTrustError::Rejected(message)) => message,
        }
    }

    #[test]
    fn a_consistent_signed_publication_is_accepted() {
        let verified = verify(&valid_envelope()).expect("valid fixture verifies");
        assert_eq!(verified.session_id_str(), "sess-1");
        assert_eq!(verified.files().len(), 2);
        assert_eq!(verified.files()[0].id(), "f-0001");
        assert_eq!(verified.files()[0].display_path(), "video/left_00000.mp4");
        assert_eq!(verified.key_fingerprint(), test_fingerprint());
        assert_eq!(verified.total_bytes(), 120);
    }

    #[test]
    fn session_detail_conversion_preserves_payload_and_encodes_material() {
        let detail = SessionDetailView {
            session_id: "sess-1".to_string(),
            revision: format!("sha256:{}", "a".repeat(64)),
            captured_at: "2026-08-01T00:00:00Z".to_string(),
            published_at: "2026-08-01T00:01:00Z".to_string(),
            duration_seconds: 12.5,
            total_bytes: 0,
            video_bytes: 0,
            file_count: 0,
            files: Vec::new(),
            publication_payload: br#"{"signed":true}"#.to_vec(),
            publication_signature: vec![0xab; ED25519_SIGNATURE_LENGTH],
            publication_public_key: vec![0xcd; ED25519_PUBLIC_KEY_LENGTH],
            publication_key_fingerprint: test_fingerprint(),
        };
        let envelope = PublicationEnvelope::try_from(&detail).expect("UTF-8 payload converts");
        assert_eq!(envelope.publication_payload, r#"{"signed":true}"#);
        assert_eq!(
            envelope.publication_signature_hex,
            "ab".repeat(ED25519_SIGNATURE_LENGTH)
        );
        assert_eq!(
            envelope.publication_public_key_hex,
            "cd".repeat(ED25519_PUBLIC_KEY_LENGTH)
        );
    }

    #[test]
    fn session_detail_conversion_rejects_non_utf8_payload() {
        let detail = SessionDetailView {
            session_id: "sess-1".to_string(),
            revision: "rev".to_string(),
            captured_at: String::new(),
            published_at: String::new(),
            duration_seconds: 0.0,
            total_bytes: 0,
            video_bytes: 0,
            file_count: 0,
            files: Vec::new(),
            publication_payload: vec![0xff],
            publication_signature: Vec::new(),
            publication_public_key: Vec::new(),
            publication_key_fingerprint: String::new(),
        };
        assert!(PublicationEnvelope::try_from(&detail).is_err());
    }

    #[test]
    fn a_changed_publication_key_fails_closed() {
        let envelope = valid_envelope();
        let rotated = format!("sha256:{}", "b".repeat(64));
        let error = PublicationTrust::new(&AcceptAll)
            .verify(&envelope, "sess-1", &rotated)
            .expect_err("a rotated key must fail closed");
        let PublicationTrustError::Rejected(message) = error;
        assert!(message.contains("SAS-confirmed"), "{message}");
    }

    #[test]
    fn a_malformed_key_identity_is_rejected_on_either_side() {
        let valid = format!("sha256:{}", "a".repeat(64));
        assert!(ensure_publication_key_identity_matches("nope", &valid).is_err());
        assert!(ensure_publication_key_identity_matches(&valid, "sha256:XYZ").is_err());
    }

    #[test]
    fn a_public_key_that_does_not_hash_to_the_fingerprint_is_rejected() {
        let mut envelope = valid_envelope();
        envelope.publication_public_key_hex = "11".repeat(ED25519_PUBLIC_KEY_LENGTH);
        assert!(error_of(&envelope).contains("public key hash"));
    }

    #[test]
    fn an_invalid_signature_is_rejected() {
        let envelope = valid_envelope();
        let error = PublicationTrust::new(&RejectAll)
            .verify(&envelope, "sess-1", &test_fingerprint())
            .expect_err("a bad signature must fail closed");
        let PublicationTrustError::Rejected(message) = error;
        assert!(message.contains("invalid Ed25519"), "{message}");
    }

    #[test]
    fn a_session_identity_mismatch_is_rejected() {
        let envelope = valid_envelope();
        let error = PublicationTrust::new(&AcceptAll)
            .verify(&envelope, "sess-other", &test_fingerprint())
            .expect_err("a detail for another session must fail closed");
        let PublicationTrustError::Rejected(message) = error;
        assert!(message.contains("requested session_id"), "{message}");
    }

    #[test]
    fn an_inventory_mismatch_between_wire_and_signed_payload_is_rejected() {
        let mut envelope = valid_envelope();
        envelope.files[0].size_bytes = 101;
        assert!(error_of(&envelope).contains("file inventory"));
    }

    #[test]
    fn duplicate_file_ids_are_rejected() {
        let mut files = default_files();
        files[1]["id"] = serde_json::json!("f-0001");
        let envelope = envelope_from(&signed_payload(&files));
        assert!(error_of(&envelope).contains("duplicate file ids"));
    }

    #[test]
    fn duplicate_display_paths_are_rejected() {
        let mut files = default_files();
        files[1]["display_path"] = serde_json::json!("video/left_00000.mp4");
        let envelope = envelope_from(&signed_payload(&files));
        assert!(error_of(&envelope).contains("duplicate file display_paths"));
    }

    #[test]
    fn unsafe_display_paths_are_rejected() {
        for unsafe_path in [
            "/absolute.mp4",
            "video/../secret",
            "video\\left.mp4",
            ".hidden",
            "",
        ] {
            let mut files = default_files();
            files[0]["display_path"] = serde_json::json!(unsafe_path);
            let envelope = envelope_from(&signed_payload(&files));
            assert!(
                error_of(&envelope).contains("display_path"),
                "path {unsafe_path:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_malformed_digest_is_rejected() {
        for bad_digest in ["B".repeat(64), "b".repeat(63), "z".repeat(64)] {
            let mut files = default_files();
            files[0]["sha256"] = serde_json::json!(bad_digest);
            let envelope = envelope_from(&signed_payload(&files));
            assert!(
                error_of(&envelope).contains("sha256"),
                "digest {bad_digest:?} must be rejected"
            );
        }
    }

    #[test]
    fn an_unknown_schema_version_is_rejected_even_with_a_valid_signature() {
        let mut payload = signed_payload(&default_files());
        payload["schema_version"] = serde_json::json!(2);
        let envelope = envelope_from(&payload);
        assert!(error_of(&envelope).contains("unsupported publication schema_version 2"));
    }

    #[test]
    fn aggregate_byte_counts_must_match_the_inventory() {
        let mut payload = signed_payload(&default_files());
        payload["total_bytes"] = serde_json::json!(121);
        refresh_revision(&mut payload);
        let mut envelope = envelope_from(&payload);
        envelope.total_bytes = 121;
        assert!(error_of(&envelope).contains("aggregate byte counts"));
    }

    #[test]
    fn publication_timestamps_must_be_real_and_ordered() {
        let mut payload = signed_payload(&default_files());
        payload["captured_at"] = serde_json::json!("not-a-timestamp");
        refresh_revision(&mut payload);
        let envelope = envelope_from(&payload);
        assert!(error_of(&envelope).contains("RFC3339"));

        let mut payload = signed_payload(&default_files());
        payload["published_at"] = serde_json::json!("2025-07-31T23:59:59Z");
        let envelope = envelope_from(&payload);
        assert!(error_of(&envelope).contains("earlier"));
    }

    #[test]
    fn rfc3339_offsets_and_leap_days_parse_consistently() {
        assert_eq!(parse_rfc3339_inner("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_inner("2026-08-01T01:00:00+01:00"),
            parse_rfc3339_inner("2026-08-01T00:00:00Z")
        );
        assert_eq!(
            parse_rfc3339_inner("2026-08-01T00:00:00.123456Z"),
            parse_rfc3339_inner("2026-08-01T00:00:00Z")
        );
        assert!(parse_rfc3339_inner("2025-02-29T00:00:00Z").is_none());
        assert!(parse_rfc3339_inner("2024-02-29T00:00:00Z").is_some());
        assert!(parse_rfc3339_inner("2026-13-01T00:00:00Z").is_none());
        assert!(parse_rfc3339_inner("2026-08-01T00:00:00").is_none());
    }

    // -----------------------------------------------------------------
    // Commit 53: plans
    // -----------------------------------------------------------------

    #[test]
    fn a_full_plan_covers_the_entire_signed_inventory() {
        let plan = verify(&valid_envelope()).unwrap().full_download_plan();
        assert!(plan.is_full_session());
        assert_eq!(plan.file_count(), 2);
        let spec = plan
            .into_job_spec(DeviceId("dev-1".to_string()), "2026-08-01")
            .expect("a full plan is a valid job spec");
        assert!(spec.full_session());
        assert_eq!(spec.requested_files().count(), 2);
    }

    #[test]
    fn a_subset_plan_downloads_exactly_the_requested_signed_files() {
        let plan = verify(&valid_envelope())
            .unwrap()
            .subset_download_plan(&[FileId("f-0002".to_string())])
            .expect("a legitimate subset is accepted");
        assert!(!plan.is_full_session());
        assert_eq!(plan.file_count(), 1);
        assert_eq!(plan.files().next().unwrap().id(), "f-0002");
        // The signed size/digest travel with the selection; they are never
        // supplied by the caller.
        assert_eq!(plan.files().next().unwrap().size_bytes(), 20);
        let spec = plan
            .into_job_spec(DeviceId("dev-1".to_string()), "2026-08-01")
            .expect("a subset plan is a valid job spec");
        assert!(!spec.full_session());
        assert_eq!(spec.session_files().len(), 2);
        assert_eq!(spec.requested_files().count(), 1);
    }

    #[test]
    fn a_subset_naming_every_file_is_a_full_session_transfer() {
        let plan = verify(&valid_envelope())
            .unwrap()
            .subset_download_plan(&[FileId("f-0001".to_string()), FileId("f-0002".to_string())])
            .expect("selecting everything is legitimate");
        assert!(plan.is_full_session());
    }

    #[test]
    fn a_plan_cannot_name_a_file_outside_the_signed_inventory() {
        let error = verify(&valid_envelope())
            .unwrap()
            .subset_download_plan(&[FileId("f-9999".to_string())])
            .expect_err("an unsigned file cannot be planned");
        let PublicationTrustError::Rejected(message) = error;
        assert!(message.contains("not part of the signed session inventory"));
    }

    #[test]
    fn a_plan_rejects_duplicate_and_empty_selections() {
        let publication = verify(&valid_envelope()).unwrap();
        assert!(publication.clone().subset_download_plan(&[]).is_err());
        assert!(publication
            .subset_download_plan(&[FileId("f-0001".to_string()), FileId("f-0001".to_string()),])
            .is_err());
    }

    #[test]
    fn rp_inline_canonicalization_matches_the_shared_unicode_and_numeric_rules() {
        let raw = br#"{"z":"s\u00e9ss","duration_seconds":121.40,"nested":{"b":2,"a":1},"publication_signature":{"signature":"00"}}"#;
        let parsed = parse_strict_json(raw).expect("strict RP fixture JSON");
        let canonical = canonicalize_rp_manifest(&parsed).expect("canonical RP payload");
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            r#"{"duration_seconds":121.4,"nested":{"a":1,"b":2},"z":"s\u00e9ss"}"#
        );
    }

    #[test]
    fn strict_json_rejects_duplicate_nonfinite_and_isolated_surrogate_values() {
        for raw in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":NaN}"#.as_slice(),
            br#"{"a":"\ud800"}"#.as_slice(),
        ] {
            assert!(parse_strict_json(raw).is_err(), "{raw:?} must fail closed");
        }
    }

    #[test]
    fn strict_json_accepts_a_valid_utf16_surrogate_pair() {
        let parsed =
            parse_strict_json(br#"{"emoji":"\ud83d\ude00"}"#).expect("pair is valid JSON Unicode");
        assert_eq!(parsed["emoji"], "😀");
    }
}
