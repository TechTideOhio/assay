use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaViolation {
    pub pointer: String,
    pub message: String,
}

pub struct SchemaValidator<'a> {
    root_schema: &'a Value,
}

impl<'a> SchemaValidator<'a> {
    pub fn new(root_schema: &'a Value) -> Self {
        Self { root_schema }
    }

    pub fn validate(&self, instance: &Value) -> Vec<SchemaViolation> {
        let mut violations = Vec::new();
        self.validate_node(self.root_schema, instance, "", &mut violations);
        violations
    }

    fn resolve_ref<'s>(&'s self, ref_str: &str) -> Option<&'s Value> {
        if let Some(target) = ref_str.strip_prefix("#/") {
            let parts: Vec<&str> = target.split('/').collect();
            let mut curr = self.root_schema;
            for part in parts {
                let unescaped = part.replace("~1", "/").replace("~0", "~");
                if let Some(next) = curr.get(&unescaped) {
                    curr = next;
                } else {
                    return None;
                }
            }
            return Some(curr);
        }
        None
    }

    fn validate_node(
        &self,
        schema: &Value,
        instance: &Value,
        pointer: &str,
        violations: &mut Vec<SchemaViolation>,
    ) {
        if let Some(b) = schema.as_bool() {
            if !b {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: "Schema evaluates to false".to_string(),
                });
            }
            return;
        }

        let Some(obj) = schema.as_object() else {
            return;
        };

        // $ref resolution
        if let Some(Value::String(r)) = obj.get("$ref") {
            if let Some(resolved) = self.resolve_ref(r) {
                self.validate_node(resolved, instance, pointer, violations);
            } else {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: format!("Unresolvable $ref: {r}"),
                });
            }
            return;
        }

        // type check
        if let Some(type_val) = obj.get("type") {
            let allowed_types: Vec<&str> = match type_val {
                Value::String(s) => vec![s.as_str()],
                Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
                _ => vec![],
            };

            let actual_type = match instance {
                Value::Null => "null",
                Value::Bool(_) => "boolean",
                Value::Number(n) => {
                    if n.is_i64() || n.is_u64() {
                        "integer"
                    } else {
                        "number"
                    }
                }
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };

            let matches = allowed_types
                .iter()
                .any(|&t| t == actual_type || (t == "number" && actual_type == "integer"));

            if !matches {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: format!(
                        "Expected type in {:?}, found '{}'",
                        allowed_types, actual_type
                    ),
                });
                return;
            }
        }

        // enum
        if let Some(Value::Array(enum_vals)) = obj.get("enum") {
            if !enum_vals.iter().any(|v| v == instance) {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: format!("Value is not in enum {:?}", enum_vals),
                });
            }
        }

        // const
        if let Some(const_val) = obj.get("const") {
            if const_val != instance {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: format!("Value does not match const {const_val}"),
                });
            }
        }

        // string constraints
        if let Value::String(s) = instance {
            let char_len = s.chars().count();
            if let Some(min_len) = obj.get("minLength").and_then(|v| v.as_u64()) {
                if (char_len as u64) < min_len {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!(
                            "String length {char_len} is less than minLength {min_len}"
                        ),
                    });
                }
            }
            if let Some(max_len) = obj.get("maxLength").and_then(|v| v.as_u64()) {
                if (char_len as u64) > max_len {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!("String length {char_len} exceeds maxLength {max_len}"),
                    });
                }
            }
            if let Some(pattern_str) = obj.get("pattern").and_then(|v| v.as_str()) {
                match Regex::new(pattern_str) {
                    Ok(re) => {
                        if !re.is_match(s) {
                            violations.push(SchemaViolation {
                                pointer: pointer.to_string(),
                                message: format!("String does not match pattern '{pattern_str}'"),
                            });
                        }
                    }
                    Err(e) => {
                        violations.push(SchemaViolation {
                            pointer: pointer.to_string(),
                            message: format!("Invalid regex pattern '{pattern_str}': {e}"),
                        });
                    }
                }
            }
            if let Some(format_str) = obj.get("format").and_then(|v| v.as_str()) {
                self.check_format(format_str, s, pointer, violations);
            }
        }

        // number constraints
        if let Value::Number(n) = instance {
            let num = n.as_f64().unwrap_or(0.0);
            if let Some(min) = obj.get("minimum").and_then(|v| v.as_f64()) {
                if num < min {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!("Value {num} is less than minimum {min}"),
                    });
                }
            }
            if let Some(max) = obj.get("maximum").and_then(|v| v.as_f64()) {
                if num > max {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!("Value {num} exceeds maximum {max}"),
                    });
                }
            }
            if let Some(emin) = obj.get("exclusiveMinimum").and_then(|v| v.as_f64()) {
                if num <= emin {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!("Value {num} is not strictly greater than {emin}"),
                    });
                }
            }
            if let Some(emax) = obj.get("exclusiveMaximum").and_then(|v| v.as_f64()) {
                if num >= emax {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!("Value {num} is not strictly less than {emax}"),
                    });
                }
            }
        }

        // array constraints
        if let Value::Array(arr) = instance {
            if let Some(min_items) = obj.get("minItems").and_then(|v| v.as_u64()) {
                if (arr.len() as u64) < min_items {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!(
                            "Array items {} is less than minItems {min_items}",
                            arr.len()
                        ),
                    });
                }
            }
            if let Some(max_items) = obj.get("maxItems").and_then(|v| v.as_u64()) {
                if (arr.len() as u64) > max_items {
                    violations.push(SchemaViolation {
                        pointer: pointer.to_string(),
                        message: format!("Array items {} exceeds maxItems {max_items}", arr.len()),
                    });
                }
            }
            if let Some(Value::Bool(true)) = obj.get("uniqueItems") {
                let mut seen = HashSet::new();
                for (idx, item) in arr.iter().enumerate() {
                    let s = item.to_string();
                    if !seen.insert(s) {
                        violations.push(SchemaViolation {
                            pointer: format!("{pointer}/{idx}"),
                            message: "Duplicate array item found with uniqueItems=true".to_string(),
                        });
                        break;
                    }
                }
            }
            if let Some(items_schema) = obj.get("items") {
                for (idx, item) in arr.iter().enumerate() {
                    let child_pointer = format!("{pointer}/{idx}");
                    self.validate_node(items_schema, item, &child_pointer, violations);
                }
            }
        }

        // object constraints
        if let Value::Object(map) = instance {
            if let Some(Value::Array(req)) = obj.get("required") {
                for req_key in req {
                    if let Some(k) = req_key.as_str() {
                        if !map.contains_key(k) {
                            violations.push(SchemaViolation {
                                pointer: pointer.to_string(),
                                message: format!("Missing required property '{k}'"),
                            });
                        }
                    }
                }
            }

            let properties_schema = obj.get("properties").and_then(|v| v.as_object());
            let additional_props = obj.get("additionalProperties");

            for (k, val) in map {
                let child_pointer = format!("{pointer}/{k}");
                let mut matched = false;

                if let Some(props) = properties_schema {
                    if let Some(sub_schema) = props.get(k) {
                        self.validate_node(sub_schema, val, &child_pointer, violations);
                        matched = true;
                    }
                }

                if !matched {
                    if let Some(add_prop) = additional_props {
                        match add_prop {
                            Value::Bool(false) => {
                                violations.push(SchemaViolation {
                                    pointer: child_pointer,
                                    message: format!("Additional property '{k}' not allowed"),
                                });
                            }
                            Value::Object(_) => {
                                self.validate_node(add_prop, val, &child_pointer, violations);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // allOf
        if let Some(Value::Array(all_of)) = obj.get("allOf") {
            for sub in all_of {
                self.validate_node(sub, instance, pointer, violations);
            }
        }

        // anyOf
        if let Some(Value::Array(any_of)) = obj.get("anyOf") {
            let mut sub_violations = Vec::new();
            let mut any_passed = false;
            for sub in any_of {
                let mut v = Vec::new();
                self.validate_node(sub, instance, pointer, &mut v);
                if v.is_empty() {
                    any_passed = true;
                    break;
                }
                sub_violations.push(v);
            }
            if !any_passed {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: "Value does not match any subschema in anyOf".to_string(),
                });
            }
        }

        // oneOf
        if let Some(Value::Array(one_of)) = obj.get("oneOf") {
            let mut passes = 0;
            for sub in one_of {
                let mut v = Vec::new();
                self.validate_node(sub, instance, pointer, &mut v);
                if v.is_empty() {
                    passes += 1;
                }
            }
            if passes != 1 {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: format!("Expected exactly 1 match in oneOf, matched {passes}"),
                });
            }
        }

        // not
        if let Some(not_schema) = obj.get("not") {
            let mut v = Vec::new();
            self.validate_node(not_schema, instance, pointer, &mut v);
            if v.is_empty() {
                violations.push(SchemaViolation {
                    pointer: pointer.to_string(),
                    message: "Value matched forbidden 'not' schema".to_string(),
                });
            }
        }
    }

    fn check_format(
        &self,
        format: &str,
        s: &str,
        pointer: &str,
        violations: &mut Vec<SchemaViolation>,
    ) {
        let valid = match format {
            "email" => s.contains('@') && s.split('@').count() == 2,
            "uri" => s.contains("://"),
            "sha256" => s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()),
            "relative-path" => {
                !s.starts_with('/') && !s.starts_with('\\') && !s.contains("..") && !s.contains(':')
            }
            "uuid" => {
                s.len() == 36
                    && s.chars().enumerate().all(|(i, c)| {
                        if i == 8 || i == 13 || i == 18 || i == 23 {
                            c == '-'
                        } else {
                            c.is_ascii_hexdigit()
                        }
                    })
            }
            "date-time" => s.len() >= 19 && (s.contains('T') || s.contains('t')),
            _ => true,
        };

        if !valid {
            violations.push(SchemaViolation {
                pointer: pointer.to_string(),
                message: format!("String '{s}' does not conform to format '{format}'"),
            });
        }
    }
}
