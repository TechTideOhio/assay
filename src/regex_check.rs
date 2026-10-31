use regex::Regex;

pub const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("GitHub Personal Access Token", r"ghp_[A-Za-z0-9_]{36,255}"),
    ("GitHub OAuth Token", r"gho_[A-Za-z0-9_]{36,255}"),
    ("GitHub Fine-Grained PAT", r"github_pat_[A-Za-z0-9_]{82}"),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("OpenAI Project Key", r"sk-proj-[A-Za-z0-9_-]{20,}"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    (
        "Bearer Authorization Header",
        r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
    ),
    (
        "Private Key Block",
        r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----",
    ),
];

pub const HOST_PATH_PATTERNS: &[(&str, &str)] = &[
    (
        "Windows User Directory",
        r"(?i)[A-Z]:\\Users\\[A-Za-z0-9_.\-]+",
    ),
    ("Linux Home Directory", r"/home/[A-Za-z0-9_.\-]+"),
    ("macOS User Directory", r"/Users/[A-Za-z0-9_.\-]+"),
];

pub fn check_regex_match(
    text: &str,
    pattern: &str,
    min_matches: Option<usize>,
    max_matches: Option<usize>,
) -> Result<(), String> {
    let re = Regex::new(pattern).map_err(|e| format!("Invalid regex '{pattern}': {e}"))?;
    let count = re.find_iter(text).count();

    let min = min_matches.unwrap_or(1);
    if count < min {
        return Err(format!(
            "Pattern '{pattern}' matched {count} times, expected at least {min}"
        ));
    }

    if let Some(max) = max_matches {
        if count > max {
            return Err(format!(
                "Pattern '{pattern}' matched {count} times, expected at most {max}"
            ));
        }
    }

    Ok(())
}

pub fn check_regex_absent(text: &str, pattern: &str) -> Result<(), String> {
    let re = Regex::new(pattern).map_err(|e| format!("Invalid regex '{pattern}': {e}"))?;
    if let Some(m) = re.find(text) {
        return Err(format!(
            "Forbidden pattern '{pattern}' matched in text: '{}'",
            m.as_str()
        ));
    }
    Ok(())
}

pub fn check_no_secret_leak(text: &str, forbid_host_paths: bool) -> Result<(), String> {
    for (name, pattern) in SECRET_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(m) = re.find(text) {
                return Err(format!(
                    "Secret leaked! {name} matched pattern '{pattern}': '{}'",
                    m.as_str()
                ));
            }
        }
    }

    if forbid_host_paths {
        for (name, pattern) in HOST_PATH_PATTERNS {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(m) = re.find(text) {
                    return Err(format!(
                        "Host-specific path leaked! {name} matched '{pattern}': '{}'",
                        m.as_str()
                    ));
                }
            }
        }
    }

    Ok(())
}
