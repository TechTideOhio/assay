use crate::error::AssayError;
use crate::spec::{AssaySuite, Severity};
use crate::suite::SuiteVerdict;
use std::path::Path;

pub fn print_verdict_terminal(verdict: &SuiteVerdict) {
    let status_str = if verdict.overall_passed {
        "PASS"
    } else {
        "FAIL"
    };

    println!(
        "=== ASSAY VERDICT [{status_str}] (score={:.2}%, duration={}ms) ===",
        verdict.total_score * 100.0,
        verdict.duration_ms
    );
    println!(
        "Suite: {} v{} | Cases: {}/{} passed | Checks: {}/{} passed | Blockers failed: {} | Model calls saved: {}",
        verdict.suite_id,
        verdict.suite_version,
        verdict.passed_cases,
        verdict.total_cases,
        verdict.passed_checks,
        verdict.total_checks,
        verdict.blocker_failures,
        verdict.model_judge_calls_saved
    );
    println!();

    for case in &verdict.cases {
        let mark = if case.passed { "[PASS]" } else { "[FAIL]" };
        println!(
            "{mark} Case '{}' (stratum: {}, score: {:.1}%)",
            case.id,
            case.stratum,
            case.score * 100.0
        );
        for chk in &case.checks {
            let chk_mark = if chk.passed { "  ✓" } else { "  ✗" };
            let sev = if chk.severity == Severity::Blocker {
                "[BLOCKER]"
            } else {
                "[GRADED]"
            };
            if chk.passed {
                println!("{chk_mark} {sev} {} ({}us)", chk.id, chk.latency_us);
            } else {
                let err = chk.error_message.as_deref().unwrap_or("Unknown error");
                println!("{chk_mark} {sev} {} -> {err}", chk.id);
            }
        }
    }
}

pub fn render_mermaid(suite: &AssaySuite) -> String {
    let mut out = String::from("flowchart TD\n");
    let suite_node = format!("    S[\"Suite: {}\"]\n", suite.suite.id);
    out.push_str(&suite_node);

    for (c_idx, case) in suite.cases.iter().enumerate() {
        let case_node_id = format!("C{c_idx}");
        out.push_str(&format!(
            "    S --> {case_node_id}[\"{}: {}\"]\n",
            case.id, case.title
        ));

        for (k_idx, check) in case.checks.iter().enumerate() {
            let check_node_id = format!("K{c_idx}_{k_idx}");
            let sev_label = if check.severity == Severity::Blocker {
                "BLOCKER"
            } else {
                "GRADED"
            };
            out.push_str(&format!(
                "    {case_node_id} -->|{sev_label}| {check_node_id}[\"{}\"]\n",
                check.id
            ));
        }
    }
    out
}

pub fn export_as_reval_cases(suite: &AssaySuite, out_dir: &Path) -> Result<(), AssayError> {
    std::fs::create_dir_all(out_dir).map_err(|e| AssayError::io(out_dir.to_path_buf(), e))?;

    for case in &suite.cases {
        let case_dir = out_dir.join(&case.id);
        std::fs::create_dir_all(&case_dir).map_err(|e| AssayError::io(&case_dir, e))?;

        let prompt_path = case_dir.join("prompt.md");
        let prompt_content = format!(
            "# Evaluation Task: {}\n\n{}\n\nStratum: {}\n",
            case.title,
            case.description
                .as_deref()
                .unwrap_or("Run deterministic verification assertions."),
            case.stratum
        );
        std::fs::write(&prompt_path, prompt_content)
            .map_err(|e| AssayError::io(&prompt_path, e))?;

        let case_toml_path = case_dir.join("case.toml");
        let toml_content = format!(
            "id = \"{}\"\ntitle = \"{}\"\nstratum = \"{}\"\nexpect = \"All deterministic checks pass with zero blocker failures.\"\nprompt = \"prompt.md\"\n\n",
            case.id, case.title, case.stratum
        );
        std::fs::write(&case_toml_path, toml_content)
            .map_err(|e| AssayError::io(&case_toml_path, e))?;
    }

    Ok(())
}
