# assay: TideOS Eval Kit (Tool 4)

<div align="center">

**Deterministic assertions first: JSON Schema validation, required fields and JSON Pointers, length limits, secret firewalls, bounded command execution, and pure-Rust in-memory SQL/RLS testing.**

[![CI](https://github.com/TechTideOhio/assay/actions/workflows/ci.yml/badge.svg)](https://github.com/TechTideOhio/assay/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/TechTideOhio/assay?color=blue&label=release)](https://github.com/TechTideOhio/assay/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Rust: 2021 / 1.82+](https://img.shields.io/badge/Rust-2021%20%2F%201.82%2B-orange.svg)](Cargo.toml)
[![Zero-FFI](https://img.shields.io/badge/Dependencies-Zero--FFI%20Pure%20Rust-purple.svg)](Cargo.toml)

[Quickstart](#60-second-quickstart) | [Core Capabilities](#core-capabilities) | [Architecture](#architecture) | [The Complete TideOS Eval Kit](#the-complete-tideos-eval-kit) | [Contributing](CONTRIBUTING.md)

</div>

---

## Why assay?

Most AI evaluation frameworks default immediately to LLM-as-a-judge prompts that suffer from non-determinism, model drift, token costs, and prompt injection vulnerabilities. When an agent breaks an API schema, corrupts a database constraint, leaks a credential, or creates a runaway loop, an LLM judge cannot be trusted to fail closed in CI.

`assay` implements **Pillar 4: Deterministic Assertions First**:

> *"JSON schema validation, regex checks, required fields, length limits, code execution, SQL that actually runs against a test DB. These are cheap, fast, and have zero variance. Reserve model-based grading for what code genuinely can't check."*

`assay` is a single, zero-dependency, pure-Rust CLI tool with no `-sys` C libraries, no external Python runtimes, and zero LLM API calls in the verification path. It evaluates assertion suites deterministically in milliseconds.

---

## Feature Comparison

| Capability | `assay` (TideOS) | Promptfoo | LangSmith / Tracing | PyTest / Unit Tests |
|---|:---:|:---:|:---:|:---:|
| **Deterministic Code First (Zero LLM)** | **Yes** (< 10ms) | Slow prompt eval | Cloud eval | Yes (Code only) |
| **JSON Schema Draft 2020-12** | **Yes** (Built-in) | Partial | No | Library required |
| **Pure-Rust In-Memory SQL & RLS Engine** | **Yes** (Zero Docker) | No | No | Needs test DB / Docker |
| **Fail-Closed Missing Evidence Firewall** | **Yes** (Conservative) | No (Skips/fails) | No | Custom code |
| **Typography & Zero Em-Dash Gate** | **Yes** (Built-in) | No | No | No |
| **Blocker Veto Short-Circuit** | **Yes** (Score 0.0) | Configurable | No (Averages) | Assert fail |
| **Cryptographic Lockfile (SHA-256)** | **Yes** (`assay.lock.json`) | No | No | No |
| **Binary Portability** | **Pure Rust** (Single binary) | Node.js | Python / Cloud | Python / C-deps |

---

## The Complete TideOS Eval Kit

| # | Tool | Crate | Release Binary | Core Responsibility |
|---|---|---|---|---|
| **1** | **`reval`** | `reval` | `2.07 MB` | **Trace Error Analysis, Gating & MCP Server** |
| **2** | **`gild`** | `gild` | `2.46 MB` | **Golden Dataset Governance & Stratification** |
| **3** | **`tessel`** | `tessel-eval` | `1.97 MB` | **Combinatorial Synthetic Scenario Generator** |
| **4** | **`assay`** | `assay-eval` | `2.09 MB` | **Deterministic Assertions First & In-Memory RLS** |
| **5** | **`tide-rill`** | `tide-rill` | `1.54 MB` | **Offline Retrieval Quality & Answer Faithfulness** |
| **6** | **`keel`** | `keel-eval` | `1.91 MB` | **Agent Trajectory Alignment & Step Efficiency (14 vs 3 calls)** |
| **7** | **`temper`** | `temper-eval` | `0.89 MB` | **Multi-Trial Reliability (pass@k vs pass^k at Real Temperature)** |
| **8** | **`parley`** | `parley-eval` | `1.77 MB` | **Simulated Users for Multi-Turn State, Memory & Policy Evals** |

---

## Core Capabilities

### 1. JSON Schema Draft 2020-12 Validation
Validates outputs against schema contracts with exact JSON Pointer diagnostics (`/artifacts/0`, `/status`):
```bash
assay schema --schema contracts/result.schema.json --target result.json
```

### 2. In-Memory SQL & RLS Policy Verification
Runs relational queries (`CREATE`, `INSERT`, `SELECT`, `WHERE`, `JOIN`, `GROUP BY`, constraints) against a pure-Rust in-memory test database in `< 5ms` without Docker:
```bash
assay sql \
  --schema fixtures/sql/schema.sql \
  --seed fixtures/sql/seed.sql \
  --query "SELECT COUNT(*) FROM tasks WHERE status = 'done';" \
  --expect-cell 3
```
Audits Supabase/Postgres migrations to ensure Row-Level Security (`ENABLE ROW LEVEL SECURITY`) is active on all tables and forbids permissive `USING (true)` policies:
```bash
assay sql --rls-migration supabase/migrations/20261030_init.sql
```

### 3. Fail-Closed Regex & Secret Firewall
Negative checks (`regex_absent`, `no_secret_leak`) fail closed if the target evidence file is absent or empty, preventing false-green results:
```bash
assay check --suite assay.toml --root .
```

### 4. Bounded Command Execution
Spawns subprocesses with hard wall-clock timeouts and assertions on exit codes, stdout substrings, and stderr regex absence:
```bash
assay exec --cmd "cargo" --args "check" --timeout-ms 5000 --expect-exit 0
```

### 5. Multi-Agent Harness & Repository Hygiene Audits
Audits agent harness run directories (`Tools/agent-harness/runs/`) for contract completeness, prompt verification context, and non-portable host path leakage:
```bash
assay harness --runs-dir Tools/agent-harness/runs
assay repo . --profile softfactory
```

---

## 60-Second Quickstart

### Installation

#### Option 1: Cargo (from source)
```bash
cargo install --git https://github.com/TechTideOhio/assay
```

#### Option 2: Pre-compiled GitHub Release Binary
Download the single standalone binary directly from [Releases](https://github.com/TechTideOhio/assay/releases/latest) for your platform (Linux x86_64, macOS Apple Silicon / Intel, Windows x86_64).

### 1. Initialize Default Assertion Suite
```bash
assay init --pack softfactory
```

### 2. Run Assertion Suite
```bash
assay check --suite assay.toml --root .
```

### 3. Generate Cryptographic Lockfile
```bash
assay lock --suite assay.toml --out assay.lock.json
```

### 4. Verify Zero Drift in CI
```bash
assay verify --suite assay.toml --lock assay.lock.json
```

---

## Machine-Readable JSON Protocol

Every subcommand supports `--json` to output TechTide's canonical harness envelope:
```json
{
  "status": "success",
  "summary": "PASS: 6/6 checks passed (100.0%, duration=4ms)",
  "next_actions": ["All deterministic assertion gates passed"],
  "artifacts": ["assay.toml"],
  "data": {
    "total_score": 1.0,
    "blocker_failures": 0,
    "model_judge_calls_saved": 1
  }
}
```

---

## Architecture

```text
assay/
├── Cargo.toml               # Rust 2021 edition, pure Rust dependencies
├── .cargo/config.toml       # Lints, target optimizations
├── .github/workflows/ci.yml # Multi-platform CI (Ubuntu, macOS, Windows)
├── .github/workflows/release.yml # Multi-target automated binary releases
├── assay.ps1                # PowerShell wrapper
├── packs/
│   └── softfactory.toml     # Calibrated assertion pack
├── fixtures/
│   ├── schema/              # Result envelope JSON Schema contracts
│   └── sql/                 # Test DB schema, seed, and RLS migrations
├── src/
│   ├── main.rs              # CLI parser (clap derive)
│   ├── lib.rs               # Library root export
│   ├── error.rs             # Typed AssayError domain enum
│   ├── envelope.rs          # HarnessEnvelope JSON protocol schema
│   ├── spec.rs              # Suite specification parser and path resolver
│   ├── schema.rs            # Engine 1: JSON Schema validator
│   ├── fields.rs            # Engine 2: RFC 6901 JSON Pointer assertions
│   ├── limits.rs            # Engine 3: Length, token & typography limits
│   ├── regex_check.rs       # Engine 4: Fail-closed regex & secret firewall
│   ├── exec.rs              # Engine 5: Bounded command execution
│   ├── sql.rs               # Engine 6: Pure-Rust in-memory SQL & RLS engine
│   ├── suite.rs             # Stratified scorer & blocker veto orchestrator
│   ├── lockfile.rs          # Framed SHA-256 lockfile generator & verifier
│   ├── repo_audit.rs        # Repository hygiene & CI workflow trigger gates
│   └── report.rs            # Terminal report & Mermaid exporter
└── tests/
    └── integration_suite.rs # 4-layer verification test suite
```

---

## Verification & Test Gates

Run the test suite and release build locally:
```bash
# Formatting
cargo fmt --all -- --check

# Clippy lints (warnings treated as errors)
cargo clippy --all-targets -- -D warnings

# Integration and property test suite
cargo test --all-targets

# Release build
cargo build --release
```

---

## License

MIT (c) 2026 TechTide AI & Alexi5000. See [LICENSE](LICENSE) for details.
