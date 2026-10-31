# Changelog

All notable changes to `assay` will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.1.0] - 2026-10-31

### Added
- Initial release of `assay` as TideOS Eval Kit Tool 4.
- Engine 1: Pure-Rust JSON Schema Draft 2020-12 validator with exact JSON Pointer diagnostics.
- Engine 2: RFC 6901 JSON Pointer assertions, required fields, and array bounds.
- Engine 3: Length, line, token estimate, and typography limits (zero-em-dash gate).
- Engine 4: Fail-closed regex, substring, and secret/host-path firewall.
- Engine 5: Bounded command execution with hard wall-clock timeouts.
- Engine 6: Pure-Rust in-memory relational SQL engine and Supabase/Postgres RLS policy verifier.
- CLI subcommands: `init`, `check`, `schema`, `sql`, `exec`, `harness`, `repo`, `lock`, `verify`, and `export`.
- Universal `--json` output with canonical `HarnessEnvelope<T>`.
- Cryptographic SHA-256 lockfile (`assay.lock.json`) and proof generator.
- Multi-platform CI and automated release binary workflows.
