# Changelog: Threat Detection Suite

All notable changes to this project will be documented in this file.

## [4.2.0] - 2026-04-04

### Added
- **Hardened Memory Forensics:** Multi-offset sampling for RWX regions and strict pointer overflow checks for x86/WOW64 compatibility.
- **WFP Kernel Telemetry:** Integrated Windows Filtering Platform (WFP) Callouts for kernel-level network beaconing detection.
- **Inverted Call Model:** Transitioned to asynchronous IRP-pending IPC for improved performance and stability.
- **Professional Remediation:** Implemented reboot-persistent file quarantine and process termination with standardized exit codes.
- **Modular Detectors:** Added specialized detectors for Registry persistence, Network C2, and Scheduled Tasks.
- **Entropy Analysis:** Integrated robust entropy calculation with magic-byte verification to identify encrypted payloads.

### Fixed
- **Critical Race Conditions:** Resolved TOCTOU vulnerabilities in network table enumeration.
- **Resource Exhaustion:** Implemented size caps and drop policies for event queues and memory logs.
- **Portability:** Replaced 32-bit `time_t` with 64-bit timestamps to prevent Y2K38 issues.
- **LOLBin Escalation:** Normalized risk scoring to prevent conceptual overflow in PowerShell command-line analysis.
- **Shared Access:** Fixed `CreateFileA` sharing violations in the driver connection bridge.

### Security
- **Self-Protection:** Added kernel-level protection for the EDR service process via object callbacks.
- **Caller Authentication:** Implemented privilege checks for IOCTL subscribers.
- **Purged Legacy Scripts:** Removed rebranding utility from repository history.

## [4.0.0] - 2026-04-04

### Changed
- **Architectural Shift:** Full transition from standalone binary to Kernel-Userland Service architecture.
- **Branding:** Formalized "Threat Detection Suite" (TDS) branding across all assets.
- **Telemetry:** Initial integration of ETW (Event Tracing for Windows) for core system visibility.
