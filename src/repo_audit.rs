use regex::Regex;
use std::path::Path;

use crate::error::AssayError;

#[derive(Debug, Clone)]
pub struct RepoAuditReport {
    pub root: String,
    pub passed: bool,
    pub findings: Vec<String>,
    pub checks_passed: usize,
    pub checks_total: usize,
}

pub fn audit_repository(root: &Path, profile: &str) -> Result<RepoAuditReport, AssayError> {
    let mut findings = Vec::new();
    let mut checks_passed = 0;
    let mut checks_total = 0;

    // Check 1: License presence
    checks_total += 1;
    let has_license = root.join("LICENSE").exists()
        || root.join("LICENSE.md").exists()
        || root.join("LICENSE.txt").exists()
        || root.join("COPYING").exists();

    if has_license {
        checks_passed += 1;
    } else {
        findings.push("Missing LICENSE or LICENSE.md at repository root".to_string());
    }

    // Check 2: Security Policy
    checks_total += 1;
    let has_security =
        root.join("SECURITY.md").exists() || root.join(".github/SECURITY.md").exists();
    if has_security {
        checks_passed += 1;
    } else {
        findings.push("Missing SECURITY.md at repository root or .github/".to_string());
    }

    // Check 3: Contributing Guide
    checks_total += 1;
    let has_contrib =
        root.join("CONTRIBUTING.md").exists() || root.join(".github/CONTRIBUTING.md").exists();
    if has_contrib {
        checks_passed += 1;
    } else {
        findings.push("Missing CONTRIBUTING.md at repository root or .github/".to_string());
    }

    // Check 4: Agent Instructions
    checks_total += 1;
    let has_agents = root.join("AGENTS.md").exists()
        || root.join("CLAUDE.md").exists()
        || root.join(".cursor/rules").exists();
    if has_agents {
        checks_passed += 1;
    } else {
        findings
            .push("Missing AGENTS.md, CLAUDE.md, or .cursor/rules agent memory file".to_string());
    }

    // Check 5: Runtime Version Pin
    checks_total += 1;
    let is_node_repo = root.join("package.json").exists();
    let is_rust_repo = root.join("Cargo.toml").exists();

    let mut pinned = false;
    if is_node_repo {
        if root.join(".nvmrc").exists()
            || root.join(".node-version").exists()
            || root.join(".tool-versions").exists()
        {
            pinned = true;
        }
    }
    if is_rust_repo {
        if root.join("rust-toolchain.toml").exists() || root.join("rust-toolchain").exists() {
            pinned = true;
        }
    }
    if !is_node_repo && !is_rust_repo {
        pinned = true;
    }

    if pinned {
        checks_passed += 1;
    } else {
        findings
            .push("Runtime version not pinned (.nvmrc or rust-toolchain.toml missing)".to_string());
    }

    // Check 6: CI Workflow Trigger on Pull Request
    checks_total += 1;
    let workflows_dir = root.join(".github/workflows");
    let mut pr_triggered = false;

    if workflows_dir.exists() && workflows_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&workflows_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension()
                    .map_or(false, |ext| ext == "yml" || ext == "yaml")
                {
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        let upper = content.to_uppercase();
                        if upper.contains("PULL_REQUEST:")
                            || upper.contains("PULL_REQUEST\n")
                            || upper.contains("[PULL_REQUEST]")
                        {
                            pr_triggered = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if pr_triggered {
        checks_passed += 1;
    } else {
        findings.push("CI workflows do not declare an automated pull_request trigger".to_string());
    }

    // Check 7: No Competing Lockfiles
    checks_total += 1;
    let has_pnpm = root.join("pnpm-lock.yaml").exists();
    let has_npm = root.join("package-lock.json").exists();
    let has_yarn = root.join("yarn.lock").exists();

    let lockfile_count = (has_pnpm as usize) + (has_npm as usize) + (has_yarn as usize);
    if lockfile_count <= 1 {
        checks_passed += 1;
    } else {
        findings.push(format!(
            "Multiple competing lockfiles detected in same root (pnpm: {has_pnpm}, npm: {has_npm}, yarn: {has_yarn})"
        ));
    }

    // Check 8: No Unencrypted .env Files
    checks_total += 1;
    let has_live_env = root.join(".env").exists()
        || root.join(".env.local").exists()
        || root.join(".env.production").exists();
    if !has_live_env {
        checks_passed += 1;
    } else {
        findings.push(
            "Live .env file committed to repository root (must use .env.example only)".to_string(),
        );
    }

    let passed = if profile == "strict" || profile == "softfactory" {
        findings.is_empty()
    } else {
        // permissive
        checks_passed >= 5
    };

    Ok(RepoAuditReport {
        root: root.display().to_string(),
        passed,
        findings,
        checks_passed,
        checks_total,
    })
}

pub fn verify_workflow_gate(
    workflow_path: &Path,
    required_trigger: &str,
    required_command_substring: &str,
) -> Result<(), AssayError> {
    if !workflow_path.exists() {
        return Err(AssayError::EvidenceMissing {
            path: workflow_path.to_path_buf(),
            detail: "Workflow file does not exist".to_string(),
        });
    }

    let content = std::fs::read_to_string(workflow_path)
        .map_err(|e| AssayError::io(workflow_path.to_path_buf(), e))?;

    let trigger_re =
        Regex::new(&format!(r"(?i)\b{}\b", regex::escape(required_trigger))).map_err(|e| {
            AssayError::AssertionFailed {
                check_id: "workflow_gate:trigger_regex".to_string(),
                message: e.to_string(),
            }
        })?;

    if !trigger_re.is_match(&content) {
        return Err(AssayError::AssertionFailed {
            check_id: format!("{}:trigger", workflow_path.display()),
            message: format!(
                "Workflow {} does not declare required trigger '{}'",
                workflow_path.display(),
                required_trigger
            ),
        });
    }

    if !content.contains(required_command_substring) {
        return Err(AssayError::AssertionFailed {
            check_id: format!("{}:command", workflow_path.display()),
            message: format!(
                "Workflow {} does not execute required command containing '{}'",
                workflow_path.display(),
                required_command_substring
            ),
        });
    }

    Ok(())
}
