#![forbid(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod exec;
pub mod fields;
pub mod limits;
pub mod lockfile;
pub mod regex_check;
pub mod repo_audit;
pub mod report;
pub mod schema;
pub mod spec;
pub mod sql;
pub mod suite;

pub use envelope::{EnvelopeStatus, HarnessEnvelope};
pub use error::AssayError;
pub use lockfile::{AssayLockfile, AssayProof};
pub use schema::SchemaValidator;
pub use spec::{AssaySuite, AssertionKind, Severity};
pub use sql::InMemoryDatabase;
pub use suite::{evaluate_suite, CaseOutcome, CheckOutcome, SuiteVerdict};
