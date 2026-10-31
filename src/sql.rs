use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::error::AssayError;

#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Float(f64),
    Text(String),
    Boolean(bool),
}

impl SqlValue {
    pub fn to_display_string(&self) -> String {
        match self {
            Self::Null => "NULL".to_string(),
            Self::Integer(i) => i.to_string(),
            Self::Float(f) => f.to_string(),
            Self::Text(s) => s.clone(),
            Self::Boolean(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TableColumn {
    pub name: String,
    pub is_pk: bool,
    pub not_null: bool,
    pub is_unique: bool,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    pub columns: Vec<TableColumn>,
    pub rows: Vec<HashMap<String, SqlValue>>,
}

impl Table {
    pub fn new(name: impl Into<String>, columns: Vec<TableColumn>) -> Self {
        Self {
            name: name.into(),
            columns,
            rows: Vec::new(),
        }
    }

    pub fn insert_row(&mut self, row: HashMap<String, SqlValue>) -> Result<(), AssayError> {
        // Check constraints
        for col in &self.columns {
            let val = row.get(&col.name).unwrap_or(&SqlValue::Null);

            if col.not_null && *val == SqlValue::Null {
                return Err(AssayError::SqlEngine {
                    message: format!(
                        "NOT NULL constraint failed on table '{}', column '{}'",
                        self.name, col.name
                    ),
                });
            }

            if (col.is_pk || col.is_unique) && *val != SqlValue::Null {
                for existing in &self.rows {
                    if let Some(ex_val) = existing.get(&col.name) {
                        if ex_val == val {
                            return Err(AssayError::SqlEngine {
                                message: format!(
                                    "UNIQUE/PK constraint failed on table '{}', column '{}': duplicate value {:?}",
                                    self.name, col.name, val
                                ),
                            });
                        }
                    }
                }
            }
        }

        self.rows.push(row);
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryDatabase {
    pub tables: HashMap<String, Table>,
}

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl InMemoryDatabase {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    pub fn execute_batch(&mut self, sql: &str) -> Result<(), AssayError> {
        let statements = split_sql_statements(sql);
        for stmt in statements {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            self.execute_statement(trimmed)?;
        }
        Ok(())
    }

    pub fn execute_statement(&mut self, sql: &str) -> Result<(), AssayError> {
        let trimmed = sql.trim().trim_end_matches(';').trim();
        let upper = trimmed.to_uppercase();

        if upper.starts_with("CREATE TABLE") {
            self.handle_create_table(trimmed)?;
        } else if upper.starts_with("INSERT INTO") {
            self.handle_insert(trimmed)?;
        } else if upper.starts_with("UPDATE") {
            self.handle_update(trimmed)?;
        } else if upper.starts_with("DELETE FROM") {
            self.handle_delete(trimmed)?;
        }
        Ok(())
    }

    fn handle_create_table(&mut self, sql: &str) -> Result<(), AssayError> {
        let open_paren = sql.find('(').ok_or_else(|| AssayError::SqlEngine {
            message: format!("Malformed CREATE TABLE: {sql}"),
        })?;
        let close_paren = sql.rfind(')').ok_or_else(|| AssayError::SqlEngine {
            message: format!("Malformed CREATE TABLE: {sql}"),
        })?;

        let header = &sql[..open_paren];
        let body = &sql[open_paren + 1..close_paren];

        let header_parts: Vec<&str> = header.split_whitespace().collect();
        let mut table_name = "";
        for (i, part) in header_parts.iter().enumerate() {
            if part.eq_ignore_ascii_case("TABLE") && i + 1 < header_parts.len() {
                let mut next = header_parts[i + 1];
                if next.eq_ignore_ascii_case("IF")
                    && i + 3 < header_parts.len()
                    && header_parts[i + 2].eq_ignore_ascii_case("NOT")
                    && header_parts[i + 3].eq_ignore_ascii_case("EXISTS")
                {
                    next = header_parts[i + 4];
                }
                table_name = next.trim_matches(|c| c == '"' || c == '`');
                break;
            }
        }

        if table_name.is_empty() {
            return Err(AssayError::SqlEngine {
                message: format!("Could not extract table name from: {header}"),
            });
        }

        let mut columns = Vec::new();
        for col_def in body.split(',') {
            let col_trimmed = col_def.trim();
            if col_trimmed.is_empty() {
                continue;
            }
            let upper_def = col_trimmed.to_uppercase();
            if upper_def.starts_with("PRIMARY KEY")
                || upper_def.starts_with("CONSTRAINT")
                || upper_def.starts_with("FOREIGN KEY")
                || upper_def.starts_with("CHECK")
            {
                continue;
            }

            let parts: Vec<&str> = col_trimmed.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let col_name = parts[0].trim_matches(|c| c == '"' || c == '`').to_string();
            let is_pk = upper_def.contains("PRIMARY KEY");
            let not_null = upper_def.contains("NOT NULL") || is_pk;
            let is_unique = upper_def.contains("UNIQUE") || is_pk;

            columns.push(TableColumn {
                name: col_name,
                is_pk,
                not_null,
                is_unique,
            });
        }

        let table = Table::new(table_name, columns);
        self.tables.insert(table_name.to_lowercase(), table);
        Ok(())
    }

    fn handle_insert(&mut self, sql: &str) -> Result<(), AssayError> {
        let values_idx =
            sql.to_uppercase()
                .find("VALUES")
                .ok_or_else(|| AssayError::SqlEngine {
                    message: format!("Malformed INSERT: missing VALUES in '{sql}'"),
                })?;

        let pre_values = sql[..values_idx].trim();
        let post_values = sql[values_idx + 6..].trim();

        let into_parts: Vec<&str> = pre_values.split_whitespace().collect();
        let mut table_name = "";
        let mut explicit_cols = Vec::new();

        for (i, part) in into_parts.iter().enumerate() {
            if part.eq_ignore_ascii_case("INTO") && i + 1 < into_parts.len() {
                let target = into_parts[i + 1];
                if let Some(p_idx) = target.find('(') {
                    table_name = target[..p_idx].trim_matches(|c| c == '"' || c == '`');
                } else {
                    table_name = target.trim_matches(|c| c == '"' || c == '`');
                }
                break;
            }
        }

        if let Some(col_start) = pre_values.find('(') {
            if let Some(col_end) = pre_values.rfind(')') {
                let cols_str = &pre_values[col_start + 1..col_end];
                for c in cols_str.split(',') {
                    explicit_cols.push(
                        c.trim()
                            .trim_matches(|ch| ch == '"' || ch == '`')
                            .to_string(),
                    );
                }
            }
        }

        let table = self
            .tables
            .get_mut(&table_name.to_lowercase())
            .ok_or_else(|| AssayError::SqlEngine {
                message: format!("Table '{table_name}' does not exist"),
            })?;

        // Extract tuples from `VALUES (...), (...)`
        let mut row_tuples = Vec::new();
        let mut depth = 0;
        let mut cur_start = 0;
        let bytes = post_values.as_bytes();

        for (idx, &b) in bytes.iter().enumerate() {
            if b == b'(' {
                if depth == 0 {
                    cur_start = idx + 1;
                }
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth == 0 {
                    row_tuples.push(&post_values[cur_start..idx]);
                }
            }
        }

        for tuple_str in row_tuples {
            let parsed_vals = parse_csv_values(tuple_str);
            let mut row = HashMap::new();

            if !explicit_cols.is_empty() {
                for (col_name, val) in explicit_cols.iter().zip(parsed_vals) {
                    row.insert(col_name.clone(), val);
                }
            } else {
                for (col, val) in table.columns.iter().zip(parsed_vals) {
                    row.insert(col.name.clone(), val);
                }
            }

            table.insert_row(row)?;
        }

        Ok(())
    }

    fn handle_update(&mut self, sql: &str) -> Result<(), AssayError> {
        let parts: Vec<&str> = sql.split_whitespace().collect();
        if parts.len() < 4 {
            return Ok(());
        }
        let table_name = parts[1].trim_matches(|c| c == '"' || c == '`');

        let upper = sql.to_uppercase();
        let set_idx = upper.find("SET").ok_or_else(|| AssayError::SqlEngine {
            message: format!("Malformed UPDATE: missing SET in '{sql}'"),
        })?;

        let where_idx = upper.find("WHERE");
        let set_clause = match where_idx {
            Some(w_idx) => sql[set_idx + 3..w_idx].trim(),
            None => sql[set_idx + 3..].trim(),
        };

        let mut assignments = HashMap::new();
        for assign in set_clause.split(',') {
            let kv: Vec<&str> = assign.split('=').collect();
            if kv.len() == 2 {
                let k = kv[0]
                    .trim()
                    .trim_matches(|c| c == '"' || c == '`')
                    .to_string();
                let v = parse_single_sql_value(kv[1].trim());
                assignments.insert(k, v);
            }
        }

        let where_clause = where_idx.map(|idx| sql[idx + 5..].trim());

        let table = self
            .tables
            .get_mut(&table_name.to_lowercase())
            .ok_or_else(|| AssayError::SqlEngine {
                message: format!("Table '{table_name}' does not exist"),
            })?;

        for row in &mut table.rows {
            if evaluate_where(row, where_clause) {
                for (k, v) in &assignments {
                    row.insert(k.clone(), v.clone());
                }
            }
        }

        Ok(())
    }

    fn handle_delete(&mut self, sql: &str) -> Result<(), AssayError> {
        let upper = sql.to_uppercase();
        let from_idx = upper.find("FROM").ok_or_else(|| AssayError::SqlEngine {
            message: format!("Malformed DELETE: missing FROM in '{sql}'"),
        })?;

        let after_from = sql[from_idx + 4..].trim();
        let where_idx = after_from.to_uppercase().find("WHERE");

        let (table_name, where_clause) = match where_idx {
            Some(w_idx) => (
                after_from[..w_idx]
                    .trim()
                    .trim_matches(|c| c == '"' || c == '`'),
                Some(after_from[w_idx + 5..].trim()),
            ),
            None => (
                after_from.trim().trim_matches(|c| c == '"' || c == '`'),
                None,
            ),
        };

        let table = self
            .tables
            .get_mut(&table_name.to_lowercase())
            .ok_or_else(|| AssayError::SqlEngine {
                message: format!("Table '{table_name}' does not exist"),
            })?;

        table.rows.retain(|row| !evaluate_where(row, where_clause));
        Ok(())
    }

    pub fn query(&self, sql: &str) -> Result<QueryResult, AssayError> {
        let trimmed = sql.trim().trim_end_matches(';').trim();
        let upper = trimmed.to_uppercase();

        if !upper.starts_with("SELECT") {
            return Err(AssayError::SqlEngine {
                message: format!("Only SELECT queries are supported in query(), got: '{trimmed}'"),
            });
        }

        let from_idx = upper.find("FROM").ok_or_else(|| AssayError::SqlEngine {
            message: format!("Missing FROM in query: '{trimmed}'"),
        })?;

        let select_clause = trimmed[6..from_idx].trim();
        let rest = trimmed[from_idx + 4..].trim();

        // Check WHERE, ORDER BY, LIMIT
        let upper_rest = rest.to_uppercase();
        let where_idx = upper_rest.find("WHERE");
        let order_idx = upper_rest.find("ORDER BY");
        let limit_idx = upper_rest.find("LIMIT");

        let mut table_name_end = rest.len();
        if let Some(i) = where_idx {
            if i < table_name_end {
                table_name_end = i;
            }
        }
        if let Some(i) = order_idx {
            if i < table_name_end {
                table_name_end = i;
            }
        }
        if let Some(i) = limit_idx {
            if i < table_name_end {
                table_name_end = i;
            }
        }

        let table_name = rest[..table_name_end]
            .trim()
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '"' || c == '`');

        let where_clause = where_idx.map(|w_pos| {
            let mut end = rest.len();
            if let Some(o_pos) = order_idx {
                if o_pos > w_pos && o_pos < end {
                    end = o_pos;
                }
            }
            if let Some(l_pos) = limit_idx {
                if l_pos > w_pos && l_pos < end {
                    end = l_pos;
                }
            }
            rest[w_pos + 5..end].trim()
        });

        let limit_num = limit_idx.and_then(|l_pos| {
            rest[l_pos + 5..]
                .trim()
                .split_whitespace()
                .next()?
                .parse::<usize>()
                .ok()
        });

        let table =
            self.tables
                .get(&table_name.to_lowercase())
                .ok_or_else(|| AssayError::SqlEngine {
                    message: format!("Table '{table_name}' does not exist"),
                })?;

        let mut filtered_rows: Vec<&HashMap<String, SqlValue>> = table
            .rows
            .iter()
            .filter(|row| evaluate_where(row, where_clause))
            .collect();

        if let Some(lim) = limit_num {
            if filtered_rows.len() > lim {
                filtered_rows.truncate(lim);
            }
        }

        // Handle SELECT projection or aggregations
        let select_upper = select_clause.to_uppercase();
        if select_upper.contains("COUNT(*)") || select_upper == "COUNT(1)" {
            return Ok(QueryResult {
                columns: vec!["count".to_string()],
                rows: vec![vec![filtered_rows.len().to_string()]],
            });
        }

        let mut out_cols = Vec::new();
        let mut out_rows = Vec::new();

        if select_clause.trim() == "*" {
            for col in &table.columns {
                out_cols.push(col.name.clone());
            }
            for row in filtered_rows {
                let mut cells = Vec::new();
                for col in &table.columns {
                    let val = row
                        .get(&col.name)
                        .map(SqlValue::to_display_string)
                        .unwrap_or_else(|| "NULL".to_string());
                    cells.push(val);
                }
                out_rows.push(cells);
            }
        } else {
            let requested_cols: Vec<String> = select_clause
                .split(',')
                .map(|c| {
                    c.trim()
                        .trim_matches(|ch| ch == '"' || ch == '`')
                        .to_string()
                })
                .collect();
            out_cols = requested_cols.clone();

            for row in filtered_rows {
                let mut cells = Vec::new();
                for col_name in &requested_cols {
                    let val = row
                        .get(col_name)
                        .map(SqlValue::to_display_string)
                        .unwrap_or_else(|| "NULL".to_string());
                    cells.push(val);
                }
                out_rows.push(cells);
            }
        }

        Ok(QueryResult {
            columns: out_cols,
            rows: out_rows,
        })
    }
}

fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut stmts = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;

    for ch in sql.chars() {
        if ch == '\'' {
            in_quote = !in_quote;
            cur.push(ch);
        } else if ch == ';' && !in_quote {
            stmts.push(cur.clone());
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    if !cur.trim().is_empty() {
        stmts.push(cur);
    }
    stmts
}

fn parse_csv_values(csv: &str) -> Vec<SqlValue> {
    let mut vals = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;

    for ch in csv.chars() {
        if ch == '\'' {
            in_quote = !in_quote;
        } else if ch == ',' && !in_quote {
            vals.push(parse_single_sql_value(&cur));
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() || !vals.is_empty() {
        vals.push(parse_single_sql_value(&cur));
    }
    vals
}

fn parse_single_sql_value(raw: &str) -> SqlValue {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("NULL") {
        return SqlValue::Null;
    }
    if trimmed.eq_ignore_ascii_case("TRUE") {
        return SqlValue::Boolean(true);
    }
    if trimmed.eq_ignore_ascii_case("FALSE") {
        return SqlValue::Boolean(false);
    }
    if let Ok(i) = trimmed.parse::<i64>() {
        return SqlValue::Integer(i);
    }
    if let Ok(f) = trimmed.parse::<f64>() {
        return SqlValue::Float(f);
    }
    SqlValue::Text(trimmed.trim_matches('\'').to_string())
}

fn evaluate_where(row: &HashMap<String, SqlValue>, where_clause: Option<&str>) -> bool {
    let Some(clause) = where_clause else {
        return true;
    };
    let trimmed = clause.trim();
    if trimmed.is_empty() {
        return true;
    }

    if let Some(eq_idx) = trimmed.find('=') {
        let col = trimmed[..eq_idx]
            .trim()
            .trim_matches(|c| c == '"' || c == '`');
        let expected_val = parse_single_sql_value(trimmed[eq_idx + 1..].trim());
        if let Some(actual) = row.get(col) {
            return actual == &expected_val;
        }
        return false;
    }

    if let Some(neq_idx) = trimmed.find("!=") {
        let col = trimmed[..neq_idx]
            .trim()
            .trim_matches(|c| c == '"' || c == '`');
        let expected_val = parse_single_sql_value(trimmed[neq_idx + 2..].trim());
        if let Some(actual) = row.get(col) {
            return actual != &expected_val;
        }
        return true;
    }

    true
}

// -------------------------------------------------------------
// PostgreSQL / Supabase RLS Policy Verifier
// -------------------------------------------------------------

pub fn verify_rls_policies(
    sql_content: &str,
    path: &Path,
    require_rls: bool,
    forbid_permissive_true: bool,
) -> Result<(), AssayError> {
    let mut created_tables = HashSet::new();
    let mut rls_enabled_tables = HashSet::new();

    // Regex for CREATE TABLE
    let table_re = Regex::new(r"(?i)CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+([a-zA-Z0-9_.\-]+)")
        .map_err(|e| AssayError::SqlEngine {
            message: e.to_string(),
        })?;

    // Regex for ENABLE ROW LEVEL SECURITY
    let rls_re = Regex::new(
        r"(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?([a-zA-Z0-9_.\-]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
    )
    .map_err(|e| AssayError::SqlEngine {
        message: e.to_string(),
    })?;

    // Regex for CREATE POLICY
    let _policy_re = Regex::new(
        r"(?i)CREATE\s+POLICY\s+([a-zA-Z0-9_.\-]+)\s+ON\s+([a-zA-Z0-9_.\-]+)",
    )
    .map_err(|e| AssayError::SqlEngine {
        message: e.to_string(),
    })?;

    for cap in table_re.captures_iter(sql_content) {
        if let Some(m) = cap.get(1) {
            let t = m.as_str().split('.').last().unwrap_or(m.as_str());
            created_tables.insert(t.trim_matches(|c| c == '"' || c == '`').to_lowercase());
        }
    }

    for cap in rls_re.captures_iter(sql_content) {
        if let Some(m) = cap.get(1) {
            let t = m.as_str().split('.').last().unwrap_or(m.as_str());
            rls_enabled_tables.insert(t.trim_matches(|c| c == '"' || c == '`').to_lowercase());
        }
    }

    if require_rls {
        for t in &created_tables {
            if !rls_enabled_tables.contains(t) {
                return Err(AssayError::RlsViolation {
                    path: path.to_path_buf(),
                    message: format!(
                        "Table '{t}' missing 'ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;'",
                    ),
                });
            }
        }
    }

    if forbid_permissive_true {
        // Search for USING (true) or WITH CHECK (true)
        let permissive_using =
            Regex::new(r"(?i)USING\s*\(\s*true\s*\)").map_err(|e| AssayError::SqlEngine {
                message: e.to_string(),
            })?;
        let permissive_check = Regex::new(r"(?i)WITH\s+CHECK\s*\(\s*true\s*\)").map_err(|e| {
            AssayError::SqlEngine {
                message: e.to_string(),
            }
        })?;

        if let Some(m) = permissive_using.find(sql_content) {
            return Err(AssayError::RlsViolation {
                path: path.to_path_buf(),
                message: format!(
                    "Forbidden permissive RLS policy detected: '{}'. Explicit non-trivial conditions required.",
                    m.as_str()
                ),
            });
        }

        if let Some(m) = permissive_check.find(sql_content) {
            return Err(AssayError::RlsViolation {
                path: path.to_path_buf(),
                message: format!(
                    "Forbidden permissive WITH CHECK policy detected: '{}'. Explicit non-trivial conditions required.",
                    m.as_str()
                ),
            });
        }
    }

    Ok(())
}
