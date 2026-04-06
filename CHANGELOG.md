# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-05

### Added
- Advanced Kernel Driver with support for Process, Thread, and Image Load notifications.
- Windows Filtering Platform (WFP) callouts for real-time network telemetry.
- Minifilter driver for file system operation monitoring.
- Behavioral Correlation Engine in user-mode for complex attack pattern detection.
- Automated Process Memory Dumping for forensic evidence collection.
- Support for Event Tracing for Windows (ETW) threat intelligence providers.
- Local pre-commit security shield with Snyk auditing.
- Industrial GitHub Actions CI/CD pipeline.

### Fixed
- Hardened LSASS protection using strict path and device prefix validation.
- Resolved kernel spinlock deadlocks and IRP cancellation race conditions.
- Fixed memory alignment UB by moving atomics outside packed structures.
- Optimized event queue management to prevent kernel pool exhaustion.

### Security
- Implemented `ObRegisterCallbacks` for EDR self-protection.
- Added detection for Early Bird APC injection and Process Hollowing.
- Obfuscated sensitive kernel strings and randomized filter altitudes.
- Added comprehensive `SECURITY.md` and `DISCLAIMER.md`.
