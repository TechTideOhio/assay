# AGENTS.md for Tools/assay

Instructions for AI coding agents operating on this crate:

- Pure Rust (2021 edition, MSRV 1.82). Zero FFI / C dependencies.
- Never introduce `.unwrap()` in production code under `src/`.
- Maintain `#![forbid(unsafe_code)]` in `lib.rs` and `main.rs`.
- Zero em-dashes (`\u2014`) and zero en-dashes (`\u2013`) in code, comments, or documentation.
- Verify with `cargo test` and run clippy with `-D warnings`.
