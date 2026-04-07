# Changelog

All notable changes to the Threat Detection Suite (TDS) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.0.0]

### Added
- **YARA Memory Scanning**: Integrated the YARA engine for high-fidelity scanning of anonymous and private executable memory pages, enabling detection of reflective loading and fileless implants.
- **Event-Driven Architecture**: Transitioned the user-mode/kernel-mode communication from synchronous polling to an asynchronous inverted call model via `IOCTL_TDS_GET_NEXT_EVENT`.
- **Network Interception**: Implemented Windows Filtering Platform (WFP) callouts at the ALE Auth Connect and Datagram Data layers (`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, `FWPM_LAYER_DATAGRAM_DATA_V4/V6`) for native network metadata extraction.
- **Self-Protection Mechanisms**: Integrated `ObRegisterCallbacks` to intercept and strip unauthorized access rights (`PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `THREAD_SET_CONTEXT`) targeting the EDR process and threads.
- **LSASS Hardening**: Enforced mandatory path validation (`\Device\HarddiskVolume` + `\Windows\System32\lsass.exe`) to prevent path-spoofing evasion attempts.
- **Forensic Pipeline**: Automated JSONL event generation and integrated a `ForensicManager` for `MiniDumpWriteDump` execution on critical alerts.
- **Threat Intelligence**: Established a `ThreatIntelManager` skeleton for real-time IoC enrichment.

### Security
- Obfuscated driver device and symbolic link names.
- Randomized the Minifilter altitude to mitigate automated evasion.
- Implemented `FLTFL_POST_OPERATION_DRAINING` checks to prevent BSODs during driver unload.
- Added strict `EVENT_QUEUE_LIMIT` to prevent kernel pool exhaustion during event floods.

### Changed
- Replaced hardcoded dependency on versions across CMake, Dockerfile, and build scripts.
- Upgraded the CI/CD pipeline to use official `snyk/actions/cpp@master` and `google/osv-scanner-action@v1` for SAST and SCA scanning with SARIF reporting.
- Restructured `TDSCommon.h` to align atomics outside of packed structs, preventing undefined behavior (UB).
