# Changelog

## [5.6.7] - 2026-08-22

### Security and runtime hardening

- Unified the driver/user event ABI and corrected the TDS device/IOCTL contract.
- Uses the secure device ACL and IOCTL access bits for policy authorization; executable names are not treated as identity.
- WFP network events carry the validated address family, remote address, port and protocol fields.
- Added bounded kernel event delivery, validated buffers, policy input and driver lifecycle cleanup.
- Connected `TDSService` to kernel events and ETW-TI callback delivery.
- Made response enforcement observe-first with explicit `contain` and `terminate` modes.
- Added local log rotation, optional forensics, OTLP/HTTP export and Windows service recovery tooling.
- Added Windows user-mode CI, shared-contract checks, WDK project metadata and WiX packaging inputs.
- Replaced the invalid GitHub Mermaid subgraph syntax with explicit renderer-safe identifiers.
- Moved the security workflow to CodeQL v4 with an explicit manual build mode and immutable action pin.

### Riesgo y actualización

- No cambia el ABI ni el driver; el cambio de CodeQL afecta únicamente la auditoría CI.
- La compilación nativa y los checks de contrato siguen siendo gates separados de la validación del driver cargado.

## [Unreleased]
- Attributed remote-thread, APC and ETW-TI responses to the decoded target PID instead of the telemetry emitter.
- Correlated ETW/APC signals during process initialization; the repository does not label this Early Bird proof until native ground-truth validation exists.
- Registered the declared Registry callback, separated read/write IOCTL access bits and removed the duplicate WFP classify guard.
- Registered process, image and thread notifications and exposed queue depth and dropped-event counters.
- Corrected the WFP contract to describe the registered ALE IPv4 callout.
- Self-protection now uses the service PID captured through the policy IOCTL instead of an executable name.

All notable changes to the Threat Detection Suite (TDS) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.6.6] - 2026-08-20

### Changed

- Published the current Windows validation boundary and build path in the README.
- Aligned the CMake project version with the release tag.
- Clarified that native driver runtime behavior still requires an isolated Windows and WDK validation environment.

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
