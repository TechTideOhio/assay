# Contributing to assay

Contributions are welcome. Please adhere to these rules before opening pull requests:

## Verification Gates

Every pull request must pass the full local gate:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release
```

## Typography and Style Rules

1. Zero em-dashes (`\u2014`) and zero en-dashes (`\u2013`) in code, comments, or documentation. Use standard colons or hyphens.
2. Zero `.unwrap()` in production code. Use `?` propagation or typed `thiserror::Error` variants.
3. Every subcommand must support `--json` and emit the canonical `HarnessEnvelope<T>`.
4. Tests must follow the four-layer verification strategy (unit, rstest, property-based SplitMix64, counterfactual fixtures).
