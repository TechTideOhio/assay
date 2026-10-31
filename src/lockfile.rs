use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::AssayError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedFile {
    pub path: String,
    pub sha256: String,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssayLockfile {
    pub schema: u32,
    pub algorithm: String,
    pub suite_id: String,
    pub suite_version: String,
    pub suite_sha256: String,
    pub files: Vec<LockedFile>,
    pub definition_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssayProof {
    pub schema: u32,
    pub suite_id: String,
    pub suite_version: String,
    pub timestamp_utc: String,
    pub definition_sha256: String,
    pub overall_passed: bool,
    pub score: f64,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub blocker_failures: usize,
    pub proof_sha256: String,
}

pub fn compute_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

pub fn compute_definition_digest(
    suite_bytes: &[u8],
    files: &[LockedFile],
    file_payloads: &[Vec<u8>],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tideos-assay-definition-v1\0");

    let suite_len = (suite_bytes.len() as u64).to_be_bytes();
    hasher.update(suite_len);
    hasher.update(suite_bytes);

    for (file, payload) in files.iter().zip(file_payloads) {
        let path_bytes = file.path.as_bytes();
        hasher.update((path_bytes.len() as u64).to_be_bytes());
        hasher.update(path_bytes);

        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
    }

    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

impl AssayLockfile {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, AssayError> {
        let p = path.as_ref();
        let content = std::fs::read_to_string(p).map_err(|e| AssayError::io(p.to_path_buf(), e))?;
        serde_json::from_str(&content).map_err(|e| AssayError::json_parse(p.to_path_buf(), e))
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), AssayError> {
        let p = path.as_ref();
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| AssayError::json_parse(p.to_path_buf(), e))?;
        std::fs::write(p, json).map_err(|e| AssayError::io(p.to_path_buf(), e))?;
        Ok(())
    }
}
