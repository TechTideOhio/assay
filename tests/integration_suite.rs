use assay::fields::{
    check_array_bounds, check_field_equals, check_field_range, check_required_fields,
    resolve_json_pointer,
};
use assay::limits::{check_length_limits, LengthLimitsSpec};
use assay::lockfile::compute_sha256_hex;
use assay::regex_check::{check_no_secret_leak, check_regex_absent, check_regex_match};
use assay::repo_audit::audit_repository;
use assay::schema::SchemaValidator;
use assay::spec::AssaySuite;
use assay::sql::{verify_rls_policies, InMemoryDatabase};
use assay::suite::evaluate_suite;
use rstest::rstest;
use serde_json::json;
use std::path::PathBuf;

// -------------------------------------------------------------
// Layer 1 & 2: JSON Schema & Pointer Table Tests
// -------------------------------------------------------------

#[rstest]
#[case(json!({"status": "success", "summary": "1234567890", "next_actions": ["a"], "artifacts": ["p/a"]}), true)]
#[case(json!({"status": "invalid_status", "summary": "1234567890", "next_actions": ["a"], "artifacts": ["p/a"]}), false)]
#[case(json!({"status": "success", "summary": "short", "next_actions": ["a"], "artifacts": ["p/a"]}), false)]
#[case(json!({"status": "success", "summary": "1234567890", "next_actions": [], "artifacts": ["p/a"]}), false)]
#[case(json!({"status": "success", "summary": "1234567890", "next_actions": ["a"], "artifacts": ["/absolute/path"]}), false)]
fn test_schema_validation_table(#[case] payload: serde_json::Value, #[case] should_pass: bool) {
    let schema_str = include_str!("../fixtures/schema/result.schema.json");
    let schema: serde_json::Value = serde_json::from_str(schema_str).expect("Valid test schema");
    let validator = SchemaValidator::new(&schema);
    let violations = validator.validate(&payload);
    assert_eq!(
        violations.is_empty(),
        should_pass,
        "Violations: {:?}",
        violations
    );
}

#[test]
fn test_json_pointers_and_fields() {
    let doc = json!({
        "status": "success",
        "nested": {
            "score": 98.5,
            "items": ["apple", "banana"]
        }
    });

    assert_eq!(
        resolve_json_pointer(&doc, "/status"),
        Some(&json!("success"))
    );
    assert_eq!(
        resolve_json_pointer(&doc, "/nested/score"),
        Some(&json!(98.5))
    );
    assert_eq!(
        resolve_json_pointer(&doc, "/nested/items/0"),
        Some(&json!("apple"))
    );
    assert_eq!(resolve_json_pointer(&doc, "/nested/missing"), None);

    assert!(check_required_fields(
        &doc,
        &["/status".to_string(), "/nested/score".to_string()],
        false
    )
    .is_ok());
    assert!(check_field_equals(&doc, "/status", &json!("success")).is_ok());
    assert!(check_field_range(&doc, "/nested/score", Some(90.0), Some(100.0)).is_ok());
    assert!(check_array_bounds(&doc, "/nested/items", Some(2), Some(5), true).is_ok());
}

// -------------------------------------------------------------
// Layer 2: Typography & Limits Tests
// -------------------------------------------------------------

#[test]
fn test_typography_and_em_dash_gate() {
    let clean_text = "Standard text with colons: clean, fast, zero variance.";
    let em_dash_text = "Bad text with em\u{2014}dash";
    let en_dash_text = "Bad text with en\u{2013}dash";

    let spec = LengthLimitsSpec {
        min_chars: Some(10),
        max_chars: Some(200),
        min_bytes: None,
        max_bytes: None,
        min_lines: None,
        max_lines: None,
        max_tokens_est: None,
        forbid_em_dash: true,
    };

    assert!(check_length_limits(clean_text, clean_text.len(), &spec).is_ok());
    assert!(check_length_limits(em_dash_text, em_dash_text.len(), &spec).is_err());
    assert!(check_length_limits(en_dash_text, en_dash_text.len(), &spec).is_err());
}

// -------------------------------------------------------------
// Layer 2 & 4: Regex & Fail-Closed Secret Tests
// -------------------------------------------------------------

#[test]
fn test_regex_and_secret_firewall() {
    let clean_log = "All tests passed with zero failures in 45ms.";
    let secret_log = "Error during dispatch: ghp_123456789012345678901234567890123456 leaked";
    let host_path_log = "Report artifact written to C:\\Users\\Admin\\project\\out.json";

    assert!(check_regex_match(clean_log, r"passed", Some(1), None).is_ok());
    assert!(check_regex_absent(clean_log, r"failed|panic").is_ok());
    assert!(check_no_secret_leak(clean_log, true).is_ok());

    assert!(check_no_secret_leak(secret_log, false).is_err());
    assert!(check_no_secret_leak(host_path_log, true).is_err());
}

// -------------------------------------------------------------
// Layer 2 & 4: In-Memory SQL & RLS Verification
// -------------------------------------------------------------

#[test]
fn test_in_memory_sql_and_constraints() {
    let mut db = InMemoryDatabase::new();
    let schema = include_str!("../fixtures/sql/schema.sql");
    let seed = include_str!("../fixtures/sql/seed.sql");

    db.execute_batch(schema).expect("Schema executes cleanly");
    db.execute_batch(seed).expect("Seed executes cleanly");

    let count_res = db
        .query("SELECT COUNT(*) FROM tasks WHERE status = 'done';")
        .expect("Query executes cleanly");
    assert_eq!(
        count_res.rows.first().and_then(|r| r.first()),
        Some(&"3".to_string())
    );

    // Test constraint enforcement: duplicate PK must fail!
    let dup_res = db.execute_statement(
        "INSERT INTO tasks (id, title, status, created_at) VALUES ('t-01', 'dup', 'done', 'now');",
    );
    assert!(
        dup_res.is_err(),
        "Duplicate PK must be rejected by SQL engine"
    );

    // Test delete and count conservation
    db.execute_statement("DELETE FROM tasks WHERE id = 't-01';")
        .expect("Delete succeeds");
    let new_count = db
        .query("SELECT COUNT(*) FROM tasks WHERE status = 'done';")
        .expect("Query succeeds");
    assert_eq!(
        new_count.rows.first().and_then(|r| r.first()),
        Some(&"2".to_string())
    );
}

#[test]
fn test_sql_rls_compliance_and_permissive_rejection() {
    let compliant_sql = include_str!("../fixtures/sql/migration_rls.sql");
    let fake_path = PathBuf::from("migration.sql");
    assert!(verify_rls_policies(compliant_sql, &fake_path, true, true).is_ok());

    // Counterfactual: permissive USING (true) must fail closed!
    let permissive_sql = "CREATE TABLE users (id TEXT PRIMARY KEY); ALTER TABLE users ENABLE ROW LEVEL SECURITY; CREATE POLICY p ON users FOR SELECT USING (true);";
    assert!(verify_rls_policies(permissive_sql, &fake_path, true, true).is_err());

    // Counterfactual: missing ENABLE ROW LEVEL SECURITY must fail closed!
    let missing_rls_sql = "CREATE TABLE users (id TEXT PRIMARY KEY); CREATE POLICY p ON users FOR SELECT USING (id = 'me');";
    assert!(verify_rls_policies(missing_rls_sql, &fake_path, true, true).is_err());
}

// -------------------------------------------------------------
// Layer 3: Property-Based Randomized Invariant Tests (SplitMix64)
// -------------------------------------------------------------

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[test]
fn test_property_sql_conservation_and_digest_determinism() {
    let mut rng = SplitMix64::new(42);
    let mut db = InMemoryDatabase::new();
    db.execute_statement("CREATE TABLE items (id INTEGER PRIMARY KEY, val INTEGER NOT NULL);")
        .expect("Table created");

    let mut expected_count = 0;
    for i in 1..=50 {
        let insert_sql = format!(
            "INSERT INTO items (id, val) VALUES ({i}, {});",
            rng.next_u64() % 100
        );
        db.execute_statement(&insert_sql).expect("Insert succeeds");
        expected_count += 1;
    }

    let q1 = db
        .query("SELECT COUNT(*) FROM items;")
        .expect("Count succeeds");
    assert_eq!(q1.rows[0][0], expected_count.to_string());

    // Delete 20 items
    for i in 1..=20 {
        let delete_sql = format!("DELETE FROM items WHERE id = {i};");
        db.execute_statement(&delete_sql).expect("Delete succeeds");
        expected_count -= 1;
    }

    let q2 = db
        .query("SELECT COUNT(*) FROM items;")
        .expect("Count succeeds");
    assert_eq!(q2.rows[0][0], expected_count.to_string());

    // SHA-256 digest determinism property
    let sample_payload = b"deterministic test payload for assay digest verification";
    let d1 = compute_sha256_hex(sample_payload);
    let d2 = compute_sha256_hex(sample_payload);
    assert_eq!(d1, d2);
    assert_eq!(d1.len(), 64);
}

// -------------------------------------------------------------
// Layer 4: Full Suite End-to-End & Counterfactual Tests
// -------------------------------------------------------------

#[test]
fn test_softfactory_suite_e2e_pass() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pack_path = root.join("packs/softfactory.toml");
    let suite = AssaySuite::load_from_file(&pack_path).expect("Load softfactory suite");

    let verdict = evaluate_suite(&suite, &root).expect("Evaluate suite");
    assert!(
        verdict.overall_passed,
        "Soft factory suite must pass completely: {:?}",
        verdict
    );
    assert_eq!(verdict.blocker_failures, 0);
    assert_eq!(verdict.model_judge_calls_saved, 1);
    assert!(verdict.total_score >= 0.99);
}

#[test]
fn test_repo_audit_on_assay_crate() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let report = audit_repository(&root, "softfactory").expect("Audit succeeds");
    // assay crate has LICENSE, SECURITY.md (will write next), CONTRIBUTING.md, AGENTS.md, etc.
    assert!(report.checks_total >= 7);
}
