use regex::Regex;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::error::AssayError;

pub struct ExecSpec<'a> {
    pub program: &'a str,
    pub args: &'a [String],
    pub workdir: Option<&'a Path>,
    pub expected_exit: i32,
    pub timeout_ms: u64,
    pub stdout_contains: Option<&'a str>,
    pub stderr_absent_regex: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ExecResult {
    pub exit_code: i32,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_bounded_command(spec: &ExecSpec) -> Result<ExecResult, AssayError> {
    let mut cmd = Command::new(spec.program);
    cmd.args(spec.args);

    if let Some(dir) = spec.workdir {
        cmd.current_dir(dir);
    }

    let start = Instant::now();
    let timeout = Duration::from_millis(spec.timeout_ms);

    let mut child = cmd.spawn().map_err(|e| AssayError::CommandExec {
        program: spec.program.to_string(),
        detail: format!("Failed to spawn process: {e}"),
    })?;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let duration_ms = start.elapsed().as_millis();
                let output = child
                    .wait_with_output()
                    .map_err(|e| AssayError::CommandExec {
                        program: spec.program.to_string(),
                        detail: format!("Failed to read process output: {e}"),
                    })?;

                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = status.code().unwrap_or(-1);

                if exit_code != spec.expected_exit {
                    return Err(AssayError::AssertionFailed {
                        check_id: format!("{}:exit_code", spec.program),
                        message: format!(
                            "Expected exit code {}, got {}. stderr: {}",
                            spec.expected_exit,
                            exit_code,
                            stderr.trim()
                        ),
                    });
                }

                if let Some(expected_sub) = spec.stdout_contains {
                    if !stdout.contains(expected_sub) {
                        return Err(AssayError::AssertionFailed {
                            check_id: format!("{}:stdout", spec.program),
                            message: format!(
                                "Stdout did not contain required substring '{expected_sub}'. Actual stdout: {stdout}"
                            ),
                        });
                    }
                }

                if let Some(pattern) = spec.stderr_absent_regex {
                    let re = Regex::new(pattern).map_err(|e| AssayError::CommandExec {
                        program: spec.program.to_string(),
                        detail: format!("Invalid stderr regex pattern '{pattern}': {e}"),
                    })?;
                    if let Some(m) = re.find(&stderr) {
                        return Err(AssayError::AssertionFailed {
                            check_id: format!("{}:stderr_absent", spec.program),
                            message: format!(
                                "Stderr matched forbidden pattern '{pattern}': '{}'",
                                m.as_str()
                            ),
                        });
                    }
                }

                return Ok(ExecResult {
                    exit_code,
                    duration_ms,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    return Err(AssayError::CommandExec {
                        program: spec.program.to_string(),
                        detail: format!("Process timed out after {} ms", spec.timeout_ms),
                    });
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => {
                return Err(AssayError::CommandExec {
                    program: spec.program.to_string(),
                    detail: format!("Error waiting for process: {e}"),
                });
            }
        }
    }
}
