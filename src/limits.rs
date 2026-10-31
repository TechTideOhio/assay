pub struct LengthLimitsSpec {
    pub min_chars: Option<usize>,
    pub max_chars: Option<usize>,
    pub min_bytes: Option<usize>,
    pub max_bytes: Option<usize>,
    pub min_lines: Option<usize>,
    pub max_lines: Option<usize>,
    pub max_tokens_est: Option<usize>,
    pub forbid_em_dash: bool,
}

pub fn check_length_limits(
    text: &str,
    raw_bytes_len: usize,
    limits: &LengthLimitsSpec,
) -> Result<(), String> {
    let char_count = text.chars().count();
    let line_count = text.lines().count();
    let token_est = (char_count + 3) / 4;

    if let Some(min_c) = limits.min_chars {
        if char_count < min_c {
            return Err(format!(
                "Character count {char_count} is below minimum {min_c}"
            ));
        }
    }

    if let Some(max_c) = limits.max_chars {
        if char_count > max_c {
            return Err(format!(
                "Character count {char_count} exceeds maximum {max_c}"
            ));
        }
    }

    if let Some(min_b) = limits.min_bytes {
        if raw_bytes_len < min_b {
            return Err(format!(
                "Byte size {raw_bytes_len} is below minimum {min_b}"
            ));
        }
    }

    if let Some(max_b) = limits.max_bytes {
        if raw_bytes_len > max_b {
            return Err(format!("Byte size {raw_bytes_len} exceeds maximum {max_b}"));
        }
    }

    if let Some(min_l) = limits.min_lines {
        if line_count < min_l {
            return Err(format!("Line count {line_count} is below minimum {min_l}"));
        }
    }

    if let Some(max_l) = limits.max_lines {
        if line_count > max_l {
            return Err(format!("Line count {line_count} exceeds maximum {max_l}"));
        }
    }

    if let Some(max_t) = limits.max_tokens_est {
        if token_est > max_t {
            return Err(format!(
                "Estimated token count {token_est} exceeds maximum {max_t}"
            ));
        }
    }

    if limits.forbid_em_dash {
        for (line_idx, line) in text.lines().enumerate() {
            for (col_idx, ch) in line.chars().enumerate() {
                if ch == '\u{2014}' {
                    return Err(format!(
                        "Forbidden em-dash (\\u2014) detected at line {}, column {}",
                        line_idx + 1,
                        col_idx + 1
                    ));
                }
                if ch == '\u{2013}' {
                    return Err(format!(
                        "Forbidden en-dash (\\u2013) detected at line {}, column {}",
                        line_idx + 1,
                        col_idx + 1
                    ));
                }
            }
        }
    }

    Ok(())
}
