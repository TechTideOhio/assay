# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Security issues should be reported responsibly:

1. Do NOT open public GitHub issues for security vulnerabilities.
2. Report vulnerabilities via private email to: `alex@techtideai.io` or through GitHub Private Vulnerability Reporting.
3. Include detailed steps to reproduce, affected versions, and proof of concept.
4. Allow reasonable time for remediation prior to public disclosure.

## Security Posture

`assay` enforces:
- `#![forbid(unsafe_code)]` across the entire crate.
- Zero external C/`-sys` dependencies.
- Zero network or LLM API calls in the verification path.
- Contained relative-path resolution to prevent directory traversal outside root.
- Rejection of Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, etc.).
