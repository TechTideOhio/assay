use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

use crate::error::AssayError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Blocker,
    Graded,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Graded
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssaySuite {
    pub suite: SuiteMeta,
    #[serde(default)]
    pub strata: Option<StrataConfig>,
    pub cases: Vec<AssertionCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteMeta {
    pub id: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrataConfig {
    #[serde(default)]
    pub primary: Option<String>,
    #[serde(default)]
    pub weights: std::collections::HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionCase {
    pub id: String,
    pub title: String,
    #[serde(default = "default_stratum")]
    pub stratum: String,
    #[serde(default)]
    pub intent: Option<String>,
    pub description: Option<String>,
    pub checks: Vec<CheckSpec>,
}

fn default_stratum() -> String {
    "core".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSpec {
    pub id: String,
    #[serde(default = "default_weight")]
    pub weight: f64,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub why: Option<String>,
    pub check: AssertionKind,
}

fn default_weight() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssertionKind {
    // 1. JSON Schema Validation
    JsonSchema {
        path: String,
        schema_path: Option<String>,
        inline_schema: Option<serde_json::Value>,
    },

    // 2. Required Fields & JSON Pointer / Path Checks
    RequiredFields {
        path: String,
        pointers: Vec<String>,
        #[serde(default)]
        allow_empty_strings: bool,
    },
    JsonFieldEquals {
        path: String,
        pointer: String,
        expected: serde_json::Value,
    },
    JsonFieldRange {
        path: String,
        pointer: String,
        min: Option<f64>,
        max: Option<f64>,
    },
    JsonArrayBounds {
        path: String,
        pointer: String,
        min_items: Option<usize>,
        max_items: Option<usize>,
        #[serde(default)]
        unique: bool,
    },

    // 3. Length, Line, Token & Typography Limits
    LengthLimits {
        path: String,
        min_chars: Option<usize>,
        max_chars: Option<usize>,
        min_bytes: Option<usize>,
        max_bytes: Option<usize>,
        min_lines: Option<usize>,
        max_lines: Option<usize>,
        max_tokens_est: Option<usize>,
        #[serde(default)]
        forbid_em_dash: bool,
    },

    // 4. Fail-Closed Regex, Substring & Secret/Path Firewall
    FileExists {
        path: String,
        min_bytes: Option<usize>,
    },
    FileAbsent {
        path: String,
    },
    RegexMatch {
        path: String,
        pattern: String,
        min_matches: Option<usize>,
        max_matches: Option<usize>,
    },
    RegexAbsent {
        path: String,
        pattern: String,
    },
    NoSecretLeak {
        path: String,
        #[serde(default)]
        forbid_absolute_host_paths: bool,
    },

    // 5. Bounded Code / Command Execution
    CommandExec {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        workdir: Option<String>,
        #[serde(default)]
        expected_exit: i32,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
        stdout_contains: Option<String>,
        stderr_absent_regex: Option<String>,
    },

    // 6. SQL Execution Against Seeded Test DB + RLS Policy Verification
    SqlQuery {
        schema_sql: Option<String>,
        seed_sql: Option<String>,
        query: String,
        expected_rows: Option<usize>,
        expected_first_cell: Option<String>,
        #[serde(default)]
        expect_error: bool,
    },
    SqlRlsPolicy {
        migration_path: String,
        #[serde(default = "default_true")]
        require_rls_on_all_tables: bool,
        #[serde(default = "default_true")]
        forbid_permissive_true: bool,
    },

    // 7. CI Workflow Trigger Gate (Addresses Finding B in 12-assay-findings.md)
    WorkflowGate {
        workflow_path: String,
        required_trigger: String,
        required_command_substring: String,
    },

    // 8. Explicit Model-Judge Reservation (Zero LLM calls by default)
    ModelJudgeReservation {
        rubric: String,
        reason_code_cannot_check: String,
    },
}

fn default_true() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    5000
}

impl AssaySuite {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, AssayError> {
        let p = path.as_ref();
        let content = std::fs::read_to_string(p).map_err(|e| AssayError::io(p.to_path_buf(), e))?;

        if p.extension().map_or(false, |ext| ext == "json") {
            serde_json::from_str(&content).map_err(|e| AssayError::json_parse(p.to_path_buf(), e))
        } else {
            toml::from_str(&content).map_err(|e| AssayError::toml_parse(p.to_path_buf(), e))
        }
    }

    pub fn total_checks(&self) -> usize {
        self.cases.iter().map(|c| c.checks.len()).sum()
    }
}

pub fn resolve_contained_path(root: &Path, rel: &str) -> Result<PathBuf, AssayError> {
    if rel.is_empty() {
        return Err(AssayError::InvalidPath {
            message: "Empty path segment is not allowed".to_string(),
        });
    }

    let raw_path = Path::new(rel);
    for comp in raw_path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                return Err(AssayError::PathEscapesRoot {
                    raw: rel.to_string(),
                    root: root.to_path_buf(),
                });
            }
            Component::ParentDir => {
                return Err(AssayError::PathEscapesRoot {
                    raw: rel.to_string(),
                    root: root.to_path_buf(),
                });
            }
            Component::Normal(seg) => {
                let seg_str = seg.to_string_lossy();
                let upper = seg_str.to_ascii_uppercase();
                let stem = upper.split('.').next().unwrap_or(&upper);
                if matches!(
                    stem,
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                ) {
                    return Err(AssayError::InvalidPath {
                        message: format!("Windows reserved device name rejected: {seg_str}"),
                    });
                }
            }
            Component::CurDir => {}
        }
    }

    let joined = root.join(raw_path);
    Ok(joined)
}
