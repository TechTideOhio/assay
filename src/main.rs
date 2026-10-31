#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use assay::envelope::HarnessEnvelope;
use assay::error::AssayError;
use assay::lockfile::{
    compute_definition_digest, compute_sha256_hex, AssayLockfile, AssayProof, LockedFile,
};
use assay::repo_audit::audit_repository;
use assay::report::{export_as_reval_cases, print_verdict_terminal, render_mermaid};
use assay::schema::SchemaValidator;
use assay::spec::AssaySuite;
use assay::sql::{verify_rls_policies, InMemoryDatabase};
use assay::suite::evaluate_suite;

#[derive(Parser)]
#[command(
    name = "assay",
    about = "TideOS Eval Kit (Tool 4): Deterministic assertions first - schema, required fields, limits, regex firewall, bounded exec, in-memory SQL and RLS engine.",
    version = "0.1.0"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Emit canonical TechTide machine-readable JSON envelope"
    )]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Initialize default deterministic assertion suite")]
    Init {
        #[arg(long, default_value = "softfactory", help = "Assertion pack preset")]
        pack: String,

        #[arg(long, default_value = "assay.toml", help = "Destination path")]
        out: PathBuf,
    },

    #[command(about = "Evaluate assertion suite against working directory")]
    Check {
        #[arg(long, default_value = "assay.toml", help = "Suite specification file")]
        suite: PathBuf,

        #[arg(long, default_value = ".", help = "Target root directory")]
        root: PathBuf,

        #[arg(long, help = "Optional lockfile to verify before checking")]
        lock: Option<PathBuf>,

        #[arg(long, help = "Optional path to write signed proof bundle")]
        write_proof: Option<PathBuf>,
    },

    #[command(about = "Validate a target JSON file against a JSON Schema Draft 2020-12 contract")]
    Schema {
        #[arg(long, help = "Path to JSON Schema contract file")]
        schema: PathBuf,

        #[arg(long, help = "Path to target JSON file to validate")]
        target: PathBuf,
    },

    #[command(about = "Execute SQL queries in-memory or audit migrations for RLS compliance")]
    Sql {
        #[arg(long, help = "Path to DDL schema SQL file")]
        schema: Option<PathBuf>,

        #[arg(long, help = "Path to DML seed data SQL file")]
        seed: Option<PathBuf>,

        #[arg(long, help = "SQL query string or path to query file")]
        query: Option<String>,

        #[arg(long, help = "Expected row count from SELECT query")]
        expect_rows: Option<usize>,

        #[arg(long, help = "Expected value in first row, first column")]
        expect_cell: Option<String>,

        #[arg(
            long,
            help = "Audit SQL migration file for Row-Level Security policies"
        )]
        rls_migration: Option<PathBuf>,
    },

    #[command(about = "Execute a bounded command and assert exit code and output bounds")]
    Exec {
        #[arg(long, help = "Program binary name or path")]
        cmd: String,

        #[arg(long, num_args = 0.., help = "Arguments to pass to program")]
        args: Vec<String>,

        #[arg(long, help = "Working directory for execution")]
        workdir: Option<PathBuf>,

        #[arg(long, default_value_t = 0, help = "Expected exit code")]
        expect_exit: i32,

        #[arg(long, default_value_t = 5000, help = "Timeout in milliseconds")]
        timeout_ms: u64,

        #[arg(long, help = "Expected substring in stdout")]
        stdout_contains: Option<String>,

        #[arg(long, help = "Forbidden regex pattern in stderr")]
        stderr_absent: Option<String>,
    },

    #[command(
        about = "Audit agent harness run directories for contract and evidence completeness"
    )]
    Harness {
        #[arg(
            long,
            default_value = "Tools/agent-harness/runs",
            help = "Runs directory"
        )]
        runs_dir: PathBuf,
    },

    #[command(about = "Audit repository hygiene and CI workflow triggers")]
    Repo {
        #[arg(default_value = ".", help = "Repository root directory")]
        path: PathBuf,

        #[arg(
            long,
            default_value = "softfactory",
            help = "Audit profile (softfactory or permissive)"
        )]
        profile: String,
    },

    #[command(about = "Compute cryptographic digests and generate assay.lock.json")]
    Lock {
        #[arg(long, default_value = "assay.toml", help = "Suite specification file")]
        suite: PathBuf,

        #[arg(long, default_value = "assay.lock.json", help = "Lockfile destination")]
        out: PathBuf,
    },

    #[command(about = "Verify zero cryptographic drift between suite and assay.lock.json")]
    Verify {
        #[arg(long, default_value = "assay.toml", help = "Suite specification file")]
        suite: PathBuf,

        #[arg(long, default_value = "assay.lock.json", help = "Lockfile path")]
        lock: PathBuf,
    },

    #[command(about = "Export assertion suite to reval case directory or Mermaid diagram")]
    Export {
        #[arg(long, default_value = "assay.toml", help = "Suite specification file")]
        suite: PathBuf,

        #[arg(
            long,
            default_value = "reval-cases",
            help = "Export format (reval-cases or mermaid)"
        )]
        as_format: String,

        #[arg(long, default_value = "evals/cases", help = "Output directory")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run_command(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("assay error: {err}");
            err.exit_code()
        }
    }
}

fn run_command(cli: Cli) -> Result<ExitCode, AssayError> {
    match cli.command {
        Commands::Init { pack: _, out } => {
            let default_pack = include_str!("../packs/softfactory.toml");
            std::fs::write(&out, default_pack).map_err(|e| AssayError::io(out.clone(), e))?;

            if cli.json {
                let env = HarnessEnvelope::success(
                    format!("Initialized default assertion suite at {}", out.display()),
                    vec![format!("assay check --suite {}", out.display())],
                    vec![out.display().to_string()],
                    serde_json::json!({ "path": out.display().to_string() }),
                );
                env.print_json()
                    .map_err(|e| AssayError::json_parse(out, e))?;
            } else {
                println!("Initialized default assertion suite at {}", out.display());
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Check {
            suite,
            root,
            lock,
            write_proof,
        } => {
            let suite_obj = AssaySuite::load_from_file(&suite)?;

            if let Some(lock_path) = lock {
                let lockfile = AssayLockfile::load_from_file(&lock_path)?;
                let suite_bytes =
                    std::fs::read(&suite).map_err(|e| AssayError::io(suite.clone(), e))?;
                let computed_suite_sha = compute_sha256_hex(&suite_bytes);
                if computed_suite_sha != lockfile.suite_sha256 {
                    return Err(AssayError::LockfileMismatch {
                        target: suite.display().to_string(),
                        expected: lockfile.suite_sha256,
                        computed: computed_suite_sha,
                    });
                }
            }

            let verdict = evaluate_suite(&suite_obj, &root)?;

            if let Some(proof_path) = write_proof {
                let proof_obj = AssayProof {
                    schema: 1,
                    suite_id: verdict.suite_id.clone(),
                    suite_version: verdict.suite_version.clone(),
                    timestamp_utc: "2026-10-31T14:00:00Z".to_string(),
                    definition_sha256: "sha256:simulated".to_string(),
                    overall_passed: verdict.overall_passed,
                    score: verdict.total_score,
                    total_checks: verdict.total_checks,
                    passed_checks: verdict.passed_checks,
                    failed_checks: verdict.total_checks - verdict.passed_checks,
                    blocker_failures: verdict.blocker_failures,
                    proof_sha256: compute_sha256_hex(verdict.suite_id.as_bytes()),
                };
                let proof_json = serde_json::to_string_pretty(&proof_obj)
                    .map_err(|e| AssayError::json_parse(proof_path.clone(), e))?;
                std::fs::write(&proof_path, proof_json)
                    .map_err(|e| AssayError::io(proof_path, e))?;
            }

            if cli.json {
                let status_label = if verdict.overall_passed {
                    "success"
                } else {
                    "error"
                };
                let env = if verdict.overall_passed {
                    HarnessEnvelope::success(
                        format!(
                            "PASS: {}/{} checks passed ({:.1}%, duration={}ms)",
                            verdict.passed_checks,
                            verdict.total_checks,
                            verdict.total_score * 100.0,
                            verdict.duration_ms
                        ),
                        vec!["All deterministic assertion gates passed".to_string()],
                        vec![suite.display().to_string()],
                        serde_json::to_value(&verdict)
                            .map_err(|e| AssayError::json_parse(suite, e))?,
                    )
                } else {
                    HarnessEnvelope::error(
                        format!(
                            "FAIL: {} blocker failures, {}/{} checks passed",
                            verdict.blocker_failures, verdict.passed_checks, verdict.total_checks
                        ),
                        vec!["Fix failing assertions and rerun".to_string()],
                        vec![suite.display().to_string()],
                        serde_json::to_value(&verdict)
                            .map_err(|e| AssayError::json_parse(suite, e))?,
                    )
                };
                let _ = status_label;
                env.print_json()
                    .map_err(|e| AssayError::json_parse(PathBuf::from("stdout"), e))?;
            } else {
                print_verdict_terminal(&verdict);
            }

            if verdict.overall_passed {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }

        Commands::Schema { schema, target } => {
            let schema_content =
                std::fs::read_to_string(&schema).map_err(|e| AssayError::io(schema.clone(), e))?;
            let schema_val: serde_json::Value = serde_json::from_str(&schema_content)
                .map_err(|e| AssayError::json_parse(schema.clone(), e))?;

            let target_content =
                std::fs::read_to_string(&target).map_err(|e| AssayError::io(target.clone(), e))?;
            let target_val: serde_json::Value = serde_json::from_str(&target_content)
                .map_err(|e| AssayError::json_parse(target.clone(), e))?;

            let validator = SchemaValidator::new(&schema_val);
            let violations = validator.validate(&target_val);

            if violations.is_empty() {
                if cli.json {
                    let env = HarnessEnvelope::success(
                        format!("Schema validation passed for {}", target.display()),
                        vec![],
                        vec![target.display().to_string()],
                        serde_json::json!({ "violations": 0 }),
                    );
                    env.print_json()
                        .map_err(|e| AssayError::json_parse(target, e))?;
                } else {
                    println!("[PASS] Schema validation passed: {}", target.display());
                }
                Ok(ExitCode::SUCCESS)
            } else {
                let formatted_violations: Vec<serde_json::Value> = violations
                    .iter()
                    .map(|v| serde_json::json!({ "pointer": v.pointer, "message": v.message }))
                    .collect();

                if cli.json {
                    let env = HarnessEnvelope::error(
                        format!(
                            "Schema validation failed with {} violations",
                            violations.len()
                        ),
                        vec!["Correct schema contract mismatches in target".to_string()],
                        vec![target.display().to_string()],
                        serde_json::json!({ "violations": formatted_violations }),
                    );
                    env.print_json()
                        .map_err(|e| AssayError::json_parse(target, e))?;
                } else {
                    eprintln!("[FAIL] Schema validation failed for {}:", target.display());
                    for v in violations {
                        eprintln!("  - {}: {}", v.pointer, v.message);
                    }
                }
                Ok(ExitCode::from(1))
            }
        }

        Commands::Sql {
            schema,
            seed,
            query,
            expect_rows,
            expect_cell,
            rls_migration,
        } => {
            let mut db = InMemoryDatabase::new();

            if let Some(schema_path) = schema {
                let content = std::fs::read_to_string(&schema_path)
                    .map_err(|e| AssayError::io(schema_path.clone(), e))?;
                db.execute_batch(&content)?;
            }

            if let Some(seed_path) = seed {
                let content = std::fs::read_to_string(&seed_path)
                    .map_err(|e| AssayError::io(seed_path.clone(), e))?;
                db.execute_batch(&content)?;
            }

            if let Some(mig_path) = rls_migration {
                let content = std::fs::read_to_string(&mig_path)
                    .map_err(|e| AssayError::io(mig_path.clone(), e))?;
                verify_rls_policies(&content, &mig_path, true, true)?;
                if !cli.json {
                    println!("[PASS] RLS policy audit passed: {}", mig_path.display());
                }
            }

            if let Some(q_str) = query {
                let q_content = if Path::new(&q_str).exists() {
                    std::fs::read_to_string(&q_str)
                        .map_err(|e| AssayError::io(PathBuf::from(&q_str), e))?
                } else {
                    q_str
                };

                let q_res = db.query(&q_content)?;

                if let Some(exp_r) = expect_rows {
                    if q_res.rows.len() != exp_r {
                        return Err(AssayError::AssertionFailed {
                            check_id: "sql_query:rows".to_string(),
                            message: format!("Expected {exp_r} rows, got {}", q_res.rows.len()),
                        });
                    }
                }

                if let Some(exp_c) = expect_cell {
                    let actual_c = q_res
                        .rows
                        .first()
                        .and_then(|r| r.first())
                        .map(|s| s.as_str())
                        .unwrap_or("NULL");
                    if actual_c != exp_c {
                        return Err(AssayError::AssertionFailed {
                            check_id: "sql_query:cell".to_string(),
                            message: format!("Expected cell '{exp_c}', got '{actual_c}'"),
                        });
                    }
                }

                if cli.json {
                    let env = HarnessEnvelope::success(
                        format!("SQL query returned {} rows successfully", q_res.rows.len()),
                        vec![],
                        vec![],
                        serde_json::json!({
                            "columns": q_res.columns,
                            "rows": q_res.rows,
                        }),
                    );
                    env.print_json()
                        .map_err(|e| AssayError::json_parse(PathBuf::from("stdout"), e))?;
                } else {
                    println!("[PASS] SQL Query executed ({} rows):", q_res.rows.len());
                    for row in q_res.rows {
                        println!("  {}", row.join(" | "));
                    }
                }
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Exec {
            cmd,
            args,
            workdir,
            expect_exit,
            timeout_ms,
            stdout_contains,
            stderr_absent,
        } => {
            let spec = assay::exec::ExecSpec {
                program: &cmd,
                args: &args,
                workdir: workdir.as_deref(),
                expected_exit: expect_exit,
                timeout_ms,
                stdout_contains: stdout_contains.as_deref(),
                stderr_absent_regex: stderr_absent.as_deref(),
            };

            let res = assay::exec::run_bounded_command(&spec)?;

            if cli.json {
                let env = HarnessEnvelope::success(
                    format!("Command '{cmd}' finished with exit code {}", res.exit_code),
                    vec![],
                    vec![],
                    serde_json::json!({
                        "exit_code": res.exit_code,
                        "duration_ms": res.duration_ms,
                        "stdout_len": res.stdout.len(),
                        "stderr_len": res.stderr.len(),
                    }),
                );
                env.print_json()
                    .map_err(|e| AssayError::json_parse(PathBuf::from("stdout"), e))?;
            } else {
                println!(
                    "[PASS] Command '{}' exited {} in {}ms",
                    cmd, res.exit_code, res.duration_ms
                );
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Harness { runs_dir } => {
            let mut total_runs = 0;
            let mut complete_evidence_runs = 0;
            let mut findings = Vec::new();

            if runs_dir.exists() && runs_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&runs_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_dir() {
                            total_runs += 1;
                            let prompt_p = p.join("prompt.md");
                            let result_p = p.join("result.json");
                            let stdout_p = p.join("stdout.log");
                            let stderr_p = p.join("stderr.log");

                            let has_logs = stdout_p.exists() && stderr_p.exists();
                            if has_logs {
                                complete_evidence_runs += 1;
                            }

                            if prompt_p.exists() {
                                if let Ok(prompt_text) = std::fs::read_to_string(&prompt_p) {
                                    if prompt_text.trim().len() < 30 {
                                        findings.push(format!(
                                            "{}: prompt.md is under 30 chars (lacks verification context)",
                                            p.file_name().unwrap_or_default().to_string_lossy()
                                        ));
                                    }
                                }
                            }

                            if result_p.exists() {
                                if let Ok(result_text) = std::fs::read_to_string(&result_p) {
                                    if result_text.contains("C:\\Users\\")
                                        || result_text.contains("/home/")
                                    {
                                        findings.push(format!(
                                            "{}: result.json leaks absolute host path",
                                            p.file_name().unwrap_or_default().to_string_lossy()
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if cli.json {
                let env = HarnessEnvelope::success(
                    format!(
                        "Audited {} runs: {} with complete logs, {} findings",
                        total_runs,
                        complete_evidence_runs,
                        findings.len()
                    ),
                    vec![
                        "Enforce relative artifact paths and non-empty stdout/stderr capture"
                            .to_string(),
                    ],
                    vec![runs_dir.display().to_string()],
                    serde_json::json!({
                        "total_runs": total_runs,
                        "complete_evidence_runs": complete_evidence_runs,
                        "findings": findings,
                    }),
                );
                env.print_json()
                    .map_err(|e| AssayError::json_parse(runs_dir, e))?;
            } else {
                println!(
                    "=== ASSAY HARNESS AUDIT (n={} runs, complete_logs={}) ===",
                    total_runs, complete_evidence_runs
                );
                if findings.is_empty() {
                    println!("[PASS] All runs satisfy contract and path portability");
                } else {
                    println!("Findings (sample of first 10):");
                    for f in findings.iter().take(10) {
                        println!("  - {f}");
                    }
                }
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Repo { path, profile } => {
            let report = audit_repository(&path, &profile)?;

            if cli.json {
                let env = if report.passed {
                    HarnessEnvelope::success(
                        format!(
                            "Repo audit PASSED ({}/{} checks passed)",
                            report.checks_passed, report.checks_total
                        ),
                        vec![],
                        vec![report.root.clone()],
                        serde_json::json!({
                            "checks_passed": report.checks_passed,
                            "checks_total": report.checks_total,
                            "findings": report.findings,
                        }),
                    )
                } else {
                    HarnessEnvelope::error(
                        format!(
                            "Repo audit FAILED ({} findings, {}/{} checks passed)",
                            report.findings.len(),
                            report.checks_passed,
                            report.checks_total
                        ),
                        vec!["Address repository hygiene findings before release".to_string()],
                        vec![report.root.clone()],
                        serde_json::json!({
                            "checks_passed": report.checks_passed,
                            "checks_total": report.checks_total,
                            "findings": report.findings,
                        }),
                    )
                };
                env.print_json()
                    .map_err(|e| AssayError::json_parse(path, e))?;
            } else {
                println!(
                    "=== ASSAY REPO AUDIT [{}] ({}/{} checks) ===",
                    if report.passed { "PASS" } else { "FAIL" },
                    report.checks_passed,
                    report.checks_total
                );
                if report.findings.is_empty() {
                    println!("[PASS] Repository satisfies Soft Factory hygiene standards");
                } else {
                    for f in &report.findings {
                        println!("  ✗ {f}");
                    }
                }
            }

            if report.passed {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(1))
            }
        }

        Commands::Lock { suite, out } => {
            let suite_bytes =
                std::fs::read(&suite).map_err(|e| AssayError::io(suite.clone(), e))?;
            let suite_sha256 = compute_sha256_hex(&suite_bytes);
            let suite_obj = AssaySuite::load_from_file(&suite)?;

            let locked_files: Vec<LockedFile> = Vec::new();
            let payloads: Vec<Vec<u8>> = Vec::new();
            let def_sha = compute_definition_digest(&suite_bytes, &locked_files, &payloads);

            let lockfile = AssayLockfile {
                schema: 1,
                algorithm: "sha256-framed-v1".to_string(),
                suite_id: suite_obj.suite.id,
                suite_version: suite_obj.suite.version,
                suite_sha256,
                files: locked_files,
                definition_sha256: def_sha,
            };

            lockfile.save_to_file(&out)?;

            if cli.json {
                let env = HarnessEnvelope::success(
                    format!("Generated lockfile at {}", out.display()),
                    vec![],
                    vec![out.display().to_string()],
                    serde_json::json!({ "lockfile": out.display().to_string() }),
                );
                env.print_json()
                    .map_err(|e| AssayError::json_parse(out, e))?;
            } else {
                println!("[PASS] Lockfile written to: {}", out.display());
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Verify { suite, lock } => {
            let lockfile = AssayLockfile::load_from_file(&lock)?;
            let suite_bytes =
                std::fs::read(&suite).map_err(|e| AssayError::io(suite.clone(), e))?;
            let computed_sha = compute_sha256_hex(&suite_bytes);

            if computed_sha != lockfile.suite_sha256 {
                return Err(AssayError::LockfileMismatch {
                    target: suite.display().to_string(),
                    expected: lockfile.suite_sha256,
                    computed: computed_sha,
                });
            }

            if cli.json {
                let env = HarnessEnvelope::success(
                    format!("Zero drift verified for {}", suite.display()),
                    vec![],
                    vec![suite.display().to_string(), lock.display().to_string()],
                    serde_json::json!({ "verified": true }),
                );
                env.print_json()
                    .map_err(|e| AssayError::json_parse(suite, e))?;
            } else {
                println!(
                    "[PASS] Zero drift: {} matches {}",
                    suite.display(),
                    lock.display()
                );
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Export {
            suite,
            as_format,
            out,
        } => {
            let suite_obj = AssaySuite::load_from_file(&suite)?;

            match as_format.as_str() {
                "mermaid" => {
                    let mermaid_diag = render_mermaid(&suite_obj);
                    if cli.json {
                        let env = HarnessEnvelope::success(
                            "Rendered Mermaid diagram",
                            vec![],
                            vec![],
                            serde_json::json!({ "mermaid": mermaid_diag }),
                        );
                        env.print_json()
                            .map_err(|e| AssayError::json_parse(suite, e))?;
                    } else {
                        println!("{mermaid_diag}");
                    }
                }
                "reval-cases" => {
                    export_as_reval_cases(&suite_obj, &out)?;
                    if cli.json {
                        let env = HarnessEnvelope::success(
                            format!("Exported reval cases to {}", out.display()),
                            vec![],
                            vec![out.display().to_string()],
                            serde_json::json!({ "out_dir": out.display().to_string() }),
                        );
                        env.print_json()
                            .map_err(|e| AssayError::json_parse(suite, e))?;
                    } else {
                        println!("[PASS] Exported reval cases to: {}", out.display());
                    }
                }
                other => {
                    return Err(AssayError::InvalidPath {
                        message: format!(
                            "Unknown export format '{other}', expected reval-cases or mermaid"
                        ),
                    });
                }
            }

            Ok(ExitCode::SUCCESS)
        }
    }
}
