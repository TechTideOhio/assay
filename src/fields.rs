use serde_json::Value;
use std::collections::HashSet;

pub fn resolve_json_pointer<'a>(root: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() || pointer == "/" {
        return Some(root);
    }

    let p = pointer.strip_prefix('/').unwrap_or(pointer);
    let segments: Vec<&str> = p.split('/').collect();

    let mut curr = root;
    for seg in segments {
        let unescaped = seg.replace("~1", "/").replace("~0", "~");
        match curr {
            Value::Object(map) => {
                if let Some(next) = map.get(&unescaped) {
                    curr = next;
                } else {
                    return None;
                }
            }
            Value::Array(arr) => {
                if let Ok(idx) = unescaped.parse::<usize>() {
                    if let Some(next) = arr.get(idx) {
                        curr = next;
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }

    Some(curr)
}

pub fn check_required_fields(
    root: &Value,
    pointers: &[String],
    allow_empty_strings: bool,
) -> Result<(), String> {
    for ptr in pointers {
        match resolve_json_pointer(root, ptr) {
            None => {
                return Err(format!("Required JSON pointer '{ptr}' not found"));
            }
            Some(Value::Null) => {
                return Err(format!("Required JSON pointer '{ptr}' has null value"));
            }
            Some(Value::String(s)) if !allow_empty_strings && s.trim().is_empty() => {
                return Err(format!(
                    "Required JSON pointer '{ptr}' has empty string value"
                ));
            }
            Some(Value::Array(a)) if a.is_empty() => {
                return Err(format!(
                    "Required JSON pointer '{ptr}' has empty array value"
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

pub fn check_field_equals(root: &Value, pointer: &str, expected: &Value) -> Result<(), String> {
    let actual = resolve_json_pointer(root, pointer)
        .ok_or_else(|| format!("JSON pointer '{pointer}' not found"))?;

    if actual != expected {
        return Err(format!(
            "JSON pointer '{pointer}' mismatch: expected {}, got {}",
            expected, actual
        ));
    }

    Ok(())
}

pub fn check_field_range(
    root: &Value,
    pointer: &str,
    min: Option<f64>,
    max: Option<f64>,
) -> Result<(), String> {
    let actual = resolve_json_pointer(root, pointer)
        .ok_or_else(|| format!("JSON pointer '{pointer}' not found"))?;

    let num = actual
        .as_f64()
        .ok_or_else(|| format!("JSON pointer '{pointer}' is not a number: {actual}"))?;

    if let Some(lo) = min {
        if num < lo {
            return Err(format!(
                "JSON pointer '{pointer}' value {num} is below minimum {lo}"
            ));
        }
    }

    if let Some(hi) = max {
        if num > hi {
            return Err(format!(
                "JSON pointer '{pointer}' value {num} exceeds maximum {hi}"
            ));
        }
    }

    Ok(())
}

pub fn check_array_bounds(
    root: &Value,
    pointer: &str,
    min_items: Option<usize>,
    max_items: Option<usize>,
    unique: bool,
) -> Result<(), String> {
    let actual = resolve_json_pointer(root, pointer)
        .ok_or_else(|| format!("JSON pointer '{pointer}' not found"))?;

    let arr = actual
        .as_array()
        .ok_or_else(|| format!("JSON pointer '{pointer}' is not an array: {actual}"))?;

    if let Some(min) = min_items {
        if arr.len() < min {
            return Err(format!(
                "Array at '{pointer}' has {} items, below minimum {min}",
                arr.len()
            ));
        }
    }

    if let Some(max) = max_items {
        if arr.len() > max {
            return Err(format!(
                "Array at '{pointer}' has {} items, exceeds maximum {max}",
                arr.len()
            ));
        }
    }

    if unique {
        let mut seen = HashSet::new();
        for (i, item) in arr.iter().enumerate() {
            let s = item.to_string();
            if !seen.insert(s) {
                return Err(format!(
                    "Array at '{pointer}' has duplicate item at index {i}"
                ));
            }
        }
    }

    Ok(())
}
