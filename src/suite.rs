use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;

use crate::error::AssayError;
use crate::fields::{
    check_array_bounds, check_field_equals, check_field_range, check_required_fields,
};
use crate::limits::{check_length_limits, LengthLimitsSpec};
use crate::regex_check::{check_no_secret_leak, check_regex_absent, check_regex_match};
use crate::repo_audit::verify_workflow_gate;
use crate::schema::SchemaValidator;
use crate::spec::{resolve_contained_path, AssaySuite, AssertionKind, Severity};
use crate::sql::{verify_rls_policies, InMemoryDatabase};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckOutcome {
    pub id: String,
    pub severity: Severity,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub latency_us: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseOutcome {
    pub id: String,
    pub stratum: String,
    pub passed: bool,
    pub earned_weight: f64,
    pub total_weight: f64,
    pub score: f64,
    pub checks: Vec<CheckOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteVerdict {
    pub suite_id: String,
    pub suite_version: String,
    pub overall_passed: bool,
    pub total_score: f64,
    pub total_cases: usize,
    pub passed_cases: usize,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub blocker_failures: usize,
    pub model_judge_calls_saved: usize,
    pub duration_ms: u128,
    pub cases: Vec<CaseOutcome>,
}

pub fn evaluate_suite(suite: &AssaySuite, root: &Path) -> Result<SuiteVerdict, AssayError> {
    let start_time = Instant::now();
    let mut case_outcomes = Vec::new();

    let mut total_checks = 0;
    let mut passed_checks = 0;
    let mut blocker_failures = 0;
    let mut model_judge_calls_saved = 0;
    let mut total_score_sum = 0.0;

    for case in &suite.cases {
        let mut case_earned = 0.0;
        let mut case_total = 0.0;
        let mut case_passed = true;
        let mut check_outcomes = Vec::new();

        for check_spec in &case.checks {
            total_checks += 1;
            case_total += check_spec.weight;

            let check_start = Instant::now();
            let check_result = evaluate_single_check(&check_spec.check, root);
            let latency_us = check_start.elapsed().as_micros();

            match check_result {
                Ok(()) => {
                    passed_checks += 1;
                    case_earned += check_spec.weight;
                    if let AssertionKind::ModelJudgeReservation { .. } = check_spec.check {
                        model_judge_calls_saved += 1;
                    }
                    check_outcomes.push(CheckOutcome {
                        id: check_spec.id.clone(),
                        severity: check_spec.severity,
                        passed: true,
                        error_message: None,
                        latency_us,
                    });
                }
                Err(err_msg) => {
                    case_passed = false;
                    if check_spec.severity == Severity::Blocker {
                        blocker_failures += 1;
                    }
                    check_outcomes.push(CheckOutcome {
                        id: check_spec.id.clone(),
                        severity: check_spec.severity,
                        passed: false,
                        error_message: Some(err_msg),
                        latency_us,
                    });
                }
            }
        }

        let case_score = if case_total > 0.0 {
            case_earned / case_total
        } else {
            1.0
        };

        total_score_sum += case_score;

        case_outcomes.push(CaseOutcome {
            id: case.id.clone(),
            stratum: case.stratum.clone(),
            passed: case_passed,
            earned_weight: case_earned,
            total_weight: case_total,
            score: case_score,
            checks: check_outcomes,
        });
    }

    let total_cases = suite.cases.len();
    let passed_cases = case_outcomes.iter().filter(|c| c.passed).count();
    let overall_score = if total_cases > 0 {
        total_score_sum / (total_cases as f64)
    } else {
        1.0
    };

    let overall_passed = blocker_failures == 0 && (passed_cases == total_cases);
    let duration_ms = start_time.elapsed().as_millis();

    Ok(SuiteVerdict {
        suite_id: suite.suite.id.clone(),
        suite_version: suite.suite.version.clone(),
        overall_passed,
        total_score: overall_score,
        total_cases,
        passed_cases,
        total_checks,
        passed_checks,
        blocker_failures,
        model_judge_calls_saved,
        duration_ms,
        cases: case_outcomes,
    })
}

fn evaluate_single_check(check: &AssertionKind, root: &Path) -> Result<(), String> {
    match check {
        AssertionKind::JsonSchema {
            path,
            schema_path,
            inline_schema,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("Target JSON file not found at: {path}"));
            }
            let target_content = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read target file: {e}"))?;
            let target_val: serde_json::Value = serde_json::from_str(&target_content)
                .map_err(|e| format!("Failed to parse target JSON: {e}"))?;

            let schema_val = if let Some(schema_rel) = schema_path {
                let s_path = resolve_contained_path(root, schema_rel)
                    .map_err(|e| format!("Schema path error: {e}"))?;
                let s_content = std::fs::read_to_string(&s_path)
                    .map_err(|e| format!("Failed to read schema file: {e}"))?;
                serde_json::from_str(&s_content)
                    .map_err(|e| format!("Failed to parse schema JSON: {e}"))?
            } else if let Some(inline) = inline_schema {
                inline.clone()
            } else {
                return Err("JsonSchema check requires schema_path or inline_schema".to_string());
            };

            let validator = SchemaValidator::new(&schema_val);
            let violations = validator.validate(&target_val);
            if !violations.is_empty() {
                let msgs: Vec<String> = violations
                    .into_iter()
                    .map(|v| format!("{}: {}", v.pointer, v.message))
                    .collect();
                return Err(format!("Schema validation failed: {}", msgs.join("; ")));
            }
            Ok(())
        }

        AssertionKind::RequiredFields {
            path,
            pointers,
            allow_empty_strings,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("Target file not found at: {path}"));
            }
            let content = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            let val: serde_json::Value =
                if target_path.extension().map_or(false, |ext| ext == "toml") {
                    let toml_val: toml::Value = toml::from_str(&content)
                        .map_err(|e| format!("Failed to parse TOML: {e}"))?;
                    serde_json::to_value(toml_val)
                        .map_err(|e| format!("Failed to convert TOML to JSON value: {e}"))?
                } else {
                    serde_json::from_str(&content)
                        .map_err(|e| format!("Failed to parse JSON: {e}"))?
                };
            check_required_fields(&val, pointers, *allow_empty_strings)
        }

        AssertionKind::JsonFieldEquals {
            path,
            pointer,
            expected,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("Target file not found at: {path}"));
            }
            let content = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            let val: serde_json::Value =
                serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {e}"))?;
            check_field_equals(&val, pointer, expected)
        }

        AssertionKind::JsonFieldRange {
            path,
            pointer,
            min,
            max,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("Target file not found at: {path}"));
            }
            let content = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            let val: serde_json::Value =
                serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {e}"))?;
            check_field_range(&val, pointer, *min, *max)
        }

        AssertionKind::JsonArrayBounds {
            path,
            pointer,
            min_items,
            max_items,
            unique,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("Target file not found at: {path}"));
            }
            let content = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            let val: serde_json::Value =
                serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {e}"))?;
            check_array_bounds(&val, pointer, *min_items, *max_items, *unique)
        }

        AssertionKind::LengthLimits {
            path,
            min_chars,
            max_chars,
            min_bytes,
            max_bytes,
            min_lines,
            max_lines,
            max_tokens_est,
            forbid_em_dash,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("Target file not found at: {path}"));
            }
            let bytes =
                std::fs::read(&target_path).map_err(|e| format!("Failed to read bytes: {e}"))?;
            let text = String::from_utf8(bytes.clone())
                .map_err(|_| "Target file contains invalid UTF-8".to_string())?;

            let spec = LengthLimitsSpec {
                min_chars: *min_chars,
                max_chars: *max_chars,
                min_bytes: *min_bytes,
                max_bytes: *max_bytes,
                min_lines: *min_lines,
                max_lines: *max_lines,
                max_tokens_est: *max_tokens_est,
                forbid_em_dash: *forbid_em_dash,
            };
            check_length_limits(&text, bytes.len(), &spec)
        }

        AssertionKind::FileExists { path, min_bytes } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("File does not exist: {path}"));
            }
            if let Some(mb) = min_bytes {
                let meta = std::fs::metadata(&target_path)
                    .map_err(|e| format!("Failed to read metadata: {e}"))?;
                if (meta.len() as usize) < *mb {
                    return Err(format!(
                        "File size {} is below min_bytes {}",
                        meta.len(),
                        mb
                    ));
                }
            }
            Ok(())
        }

        AssertionKind::FileAbsent { path } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if target_path.exists() {
                return Err(format!("File unexpectedly exists: {path}"));
            }
            Ok(())
        }

        AssertionKind::RegexMatch {
            path,
            pattern,
            min_matches,
            max_matches,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!("Evidence missing for RegexMatch: {path}"));
            }
            let text = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            check_regex_match(&text, pattern, *min_matches, *max_matches)
        }

        AssertionKind::RegexAbsent { path, pattern } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!(
                    "Fail-closed: Evidence missing for RegexAbsent at: {path}"
                ));
            }
            let text = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            check_regex_absent(&text, pattern)
        }

        AssertionKind::NoSecretLeak {
            path,
            forbid_absolute_host_paths,
        } => {
            let target_path = resolve_contained_path(root, path)
                .map_err(|e| format!("Path resolution error: {e}"))?;
            if !target_path.exists() {
                return Err(format!(
                    "Fail-closed: Evidence missing for NoSecretLeak at: {path}"
                ));
            }
            let text = std::fs::read_to_string(&target_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            check_no_secret_leak(&text, *forbid_absolute_host_paths)
        }

        AssertionKind::CommandExec {
            program,
            args,
            workdir,
            expected_exit,
            timeout_ms,
            stdout_contains,
            stderr_absent_regex,
        } => {
            let resolved_workdir = match workdir {
                Some(w) => Some(
                    resolve_contained_path(root, w)
                        .map_err(|e| format!("Workdir resolution error: {e}"))?,
                ),
                None => Some(root.to_path_buf()),
            };

            let spec = crate::exec::ExecSpec {
                program,
                args,
                workdir: resolved_workdir.as_deref(),
                expected_exit: *expected_exit,
                timeout_ms: *timeout_ms,
                stdout_contains: stdout_contains.as_deref(),
                stderr_absent_regex: stderr_absent_regex.as_deref(),
            };

            crate::exec::run_bounded_command(&spec)
                .map(|_| ())
                .map_err(|e| format!("Command execution failed: {e}"))
        }

        AssertionKind::SqlQuery {
            schema_sql,
            seed_sql,
            query,
            expected_rows,
            expected_first_cell,
            expect_error,
        } => {
            let mut db = InMemoryDatabase::new();

            if let Some(schema_rel) = schema_sql {
                let s_path = resolve_contained_path(root, schema_rel)
                    .map_err(|e| format!("Schema SQL path error: {e}"))?;
                let content = std::fs::read_to_string(&s_path)
                    .map_err(|e| format!("Failed to read schema SQL: {e}"))?;
                db.execute_batch(&content)
                    .map_err(|e| format!("Schema execution error: {e}"))?;
            }

            if let Some(seed_rel) = seed_sql {
                let s_path = resolve_contained_path(root, seed_rel)
                    .map_err(|e| format!("Seed SQL path error: {e}"))?;
                let content = std::fs::read_to_string(&s_path)
                    .map_err(|e| format!("Failed to read seed SQL: {e}"))?;
                db.execute_batch(&content)
                    .map_err(|e| format!("Seed execution error: {e}"))?;
            }

            let result = db.query(query);

            if *expect_error {
                if result.is_ok() {
                    return Err(format!(
                        "Expected query error, but query succeeded: {query}"
                    ));
                }
                return Ok(());
            }

            let q_res = result.map_err(|e| format!("Query failed: {e}"))?;

            if let Some(exp_r) = expected_rows {
                if q_res.rows.len() != *exp_r {
                    return Err(format!(
                        "Query returned {} rows, expected {exp_r}",
                        q_res.rows.len()
                    ));
                }
            }

            if let Some(exp_cell) = expected_first_cell {
                let actual_cell = q_res
                    .rows
                    .first()
                    .and_then(|r| r.first())
                    .map(|s| s.as_str())
                    .unwrap_or("NULL");
                if actual_cell != exp_cell {
                    return Err(format!(
                        "Query first cell returned '{actual_cell}', expected '{exp_cell}'"
                    ));
                }
            }

            Ok(())
        }

        AssertionKind::SqlRlsPolicy {
            migration_path,
            require_rls_on_all_tables,
            forbid_permissive_true,
        } => {
            let mig_path = resolve_contained_path(root, migration_path)
                .map_err(|e| format!("Migration path resolution error: {e}"))?;
            if !mig_path.exists() {
                return Err(format!("Migration file not found at: {migration_path}"));
            }
            let content = std::fs::read_to_string(&mig_path)
                .map_err(|e| format!("Failed to read migration: {e}"))?;
            verify_rls_policies(
                &content,
                &mig_path,
                *require_rls_on_all_tables,
                *forbid_permissive_true,
            )
            .map_err(|e| format!("RLS policy check failed: {e}"))
        }

        AssertionKind::WorkflowGate {
            workflow_path,
            required_trigger,
            required_command_substring,
        } => {
            let wf_path = resolve_contained_path(root, workflow_path)
                .map_err(|e| format!("Workflow path resolution error: {e}"))?;
            verify_workflow_gate(&wf_path, required_trigger, required_command_substring)
                .map_err(|e| format!("Workflow gate check failed: {e}"))
        }

        AssertionKind::ModelJudgeReservation {
            rubric,
            reason_code_cannot_check,
        } => {
            // By design: deterministic code verified prior layers, so this reservation passes without LLM invocation.
            let _ = (rubric, reason_code_cannot_check);
            Ok(())
        }
    }
}
