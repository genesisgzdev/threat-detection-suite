# Threat Detection Suite v4.2.0

Threat Detection Suite (Endpoint Detection and Response) is a professional-grade security suite designed for deep system visibility, real-time threat detection, and automated incident response on Windows platforms. Version 4.2.0 introduces a hardened Kernel Driver + Userland Service architecture, leveraging advanced Event Tracing for Windows (ETW), Windows Filtering Platform (WFP), and a multi-stage behavioral correlation engine.

## Key Architectural Components

### 1. ThreatDetectionKernel (Kernel-Mode Driver)
A high-performance Windows kernel-mode driver (WDM/WDF) that provides:
- **Process and Thread Notifications:** Real-time monitoring of process creation and thread injection via `PsSetCreateProcessNotifyRoutineEx` and `PsSetCreateThreadNotifyRoutine`.
- **WFP Callouts:** Monitoring and analyzing network connections at the kernel level for beaconing detection.
- **Inverted Call Model:** High-performance asynchronous event delivery to user-mode via pending IRPs.
- **Image Load Notifications:** Detection of DLL injection and reflective loading via `PsSetLoadImageNotifyRoutine`.
- **Self-Protection:** Object callback protection for the EDR service process and critical system entities like LSASS.

> **Note:** The driver is currently in active development. Ensure the Windows Driver Kit (WDK) is installed for compilation.

### 2. ThreatDetectionService (User-Mode Service)
A persistent Windows service acting as the central intelligence hub:
- **ETW Orchestration:** Consumes and analyzes Event Tracing for Windows (ETW) streams for DNS queries, file operations, and TI events.
- **Behavioral Correlation Engine:** Correlates disparate system events to identify complex attack patterns using stateful tracking.
- **Policy Enforcement:** Communicates with the kernel driver via secure IOCTLs to enforce detection rules and automated remediation actions.

### 3. TDSEngine (Detection & Analytics)
A modular engine implementing:
- **Heuristic Pattern Matching:** Signature-less detection of known exploitation techniques (e.g., LOLBins, Process Hollowing).
- **Memory Forensic Analysis:** Multi-offset sampling of process memory for shellcode, RWX pages, and hidden hooks.
- **Network Traffic Correlation:** Identifying C2 communication patterns and data exfiltration attempts via statistical analysis.

## Forensic Capabilities
- **Event Journaling:** High-fidelity logging of system events with resource exhaustion mitigation.
- **Process Lineage Tracking:** Full visibility into parent-child process relationships and execution chains.
- **Automated Remediation:** Real-time process termination, registry cleanup, and secure file quarantine with reboot-persistent fallback.

## Technical Specifications
- **Core Standards:** C++17 (User-mode), C11 (Kernel-mode).
- **Minimum OS:** Windows 10 (Build 1809+) / Windows Server 2019.
- **Build System:** CMake + WDK (Windows Driver Kit).
- **Communication:** Secure IOCTL channel with caller authentication.

## Project Structure
```text
.
├── ThreatDetectionSuite/
│   ├── TDSCommon/      # Shared headers and packed IPC structures
│   ├── TDSDriver/      # Kernel-mode driver source (WDK/C11)
│   ├── TDSEngine/      # Behavioral correlation and detection logic
│   │   ├── collectors/ # ETW and Telemetry collectors
│   │   ├── correlator/ # Stateful event correlation
│   │   └── detectors/  # Specialized detection modules (Persistence, Registry, Net)
│   └── TDSScanner/     # Memory, Hook, and Entropy forensic scanners
├── tools/
│   └── bridge/         # Integration Bridge & Test Utility
└── tests/              # Integration and unit tests
```

## Licensing
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
