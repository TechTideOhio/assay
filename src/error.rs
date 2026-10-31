use std::path::PathBuf;
use std::process::ExitCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AssayError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse TOML at {path}: {source}")]
    TomlParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("Failed to parse JSON at {path}: {source}")]
    JsonParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Path traversal rejected: path '{raw}' escapes root '{root}'")]
    PathEscapesRoot { raw: String, root: PathBuf },

    #[error("Invalid path: {message}")]
    InvalidPath { message: String },

    #[error("Missing required evidence file at {path}: {detail}")]
    EvidenceMissing { path: PathBuf, detail: String },

    #[error("JSON Schema error: {message} at pointer {pointer}")]
    SchemaValidation { pointer: String, message: String },

    #[error("Assertion failure in check '{check_id}': {message}")]
    AssertionFailed { check_id: String, message: String },

    #[error("Blocker failure in check '{check_id}': {message}")]
    BlockerFailed { check_id: String, message: String },

    #[error("Lockfile mismatch for '{target}': expected {expected}, computed {computed}")]
    LockfileMismatch {
        target: String,
        expected: String,
        computed: String,
    },

    #[error("Command execution error: {program} failed: {detail}")]
    CommandExec { program: String, detail: String },

    #[error("SQL execution error: {message}")]
    SqlEngine { message: String },

    #[error("RLS policy violation in migration {path}: {message}")]
    RlsViolation { path: PathBuf, message: String },

    #[error("Repository audit failure: {message}")]
    RepoAudit { message: String },
}

impl AssayError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn toml_parse(path: impl Into<PathBuf>, source: toml::de::Error) -> Self {
        Self::TomlParse {
            path: path.into(),
            source,
        }
    }

    pub fn json_parse(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::JsonParse {
            path: path.into(),
            source,
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        match self {
            // Quality gate or assertion failure -> exit 1
            Self::AssertionFailed { .. }
            | Self::BlockerFailed { .. }
            | Self::RlsViolation { .. }
            | Self::RepoAudit { .. }
            | Self::SchemaValidation { .. }
            | Self::EvidenceMissing { .. } => ExitCode::from(1),

            // Input, I/O, parsing, usage, path security, or lock drift -> exit 2
            Self::Io { .. }
            | Self::TomlParse { .. }
            | Self::JsonParse { .. }
            | Self::PathEscapesRoot { .. }
            | Self::InvalidPath { .. }
            | Self::LockfileMismatch { .. }
            | Self::CommandExec { .. }
            | Self::SqlEngine { .. } => ExitCode::from(2),
        }
    }
}
