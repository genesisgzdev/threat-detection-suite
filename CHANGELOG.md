# Changelog

All notable changes to the Threat Detection Suite (TDS) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-05-20

### Added
- **100% Event-Driven Core**: Replaced all legacy polling logic with native kernel callbacks.
- **Kernel Interception Engine**: 
  - Implementation of `PsSetCreateProcessNotifyRoutineEx` for deep process lineage tracking.
  - Windows Filtering Platform (WFP) Callouts for L3/L4 network interception.
  - File System Minifilter for pre-operation I/O monitoring and ransomware mitigation.
- **ETW-Ti Support**: Integrated Event Tracing for Windows - Threat Intelligence for advanced telemetry (injection detection, memory allocation).
- **Self-Protection Core**: Implemented `ObRegisterCallbacks` to shield EDR processes from termination and memory manipulation.
- **IPC Layer**: High-performance "Inverted Call" model for low-latency kernel-to-user communication.
- **Forensic Pipeline**: Automated JSONL event generation and GTI (Google Threat Intelligence) enrichment bridge.

### Security
- Hardened driver altitudes and randomized device object names.
- Mandatory Snyk SAST and OSV-Scanner checks in CI/CD.
- Responsible disclosure policy ([SECURITY.md](SECURITY.md)) and ethical use guidelines ([DISCLAIMER.md](DISCLAIMER.md)).
