use ylx_transfer_core::domain::{FileId, JobFileSpec, PublicationMaterial};

/// A deterministic, well-formed 64-hex-character SHA-256 string.
pub fn sha(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

pub fn file(id: &str, size: u64, seed: u8) -> JobFileSpec {
    JobFileSpec::new(
        FileId(id.to_string()),
        format!("video/{id}.mp4"),
        size,
        sha(seed),
    )
    .expect("fixture file spec is valid")
}

pub fn publication(revision: &str) -> PublicationMaterial {
    PublicationMaterial::new(revision, vec![1, 2, 3, 4], vec![7u8; 64], vec![9u8; 32])
        .expect("fixture publication material is valid")
}
