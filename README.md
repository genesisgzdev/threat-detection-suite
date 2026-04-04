# Nexus Intelligence EDR v4.0

Nexus Intelligence EDR (Endpoint Detection and Response) is a next-generation, professional-grade security suite designed for deep system visibility, real-time threat detection, and automated incident response on Windows platforms. Version 4.0 introduces a robust Kernel Driver + Userland Service architecture, leveraging advanced Event Tracing for Windows (ETW) and a multi-stage behavioral correlation engine.

## Key Architectural Components

### 1. NexusKernel (Kernel-Mode Driver)
A high-performance Windows kernel-mode driver (WDM/WDF) that provides:
- **Process and Thread Notifications:** Real-time monitoring of process creation and thread injection via `PsSetCreateProcessNotifyRoutine` and `PsSetCreateThreadNotifyRoutine`.
- **Registry Callbacks:** Monitoring and blocking malicious registry modifications using the Configuration Manager (`CmRegisterCallbackEx`).
- **File System Filter:** Advanced monitoring of I/O operations and file integrity using Minifilter technology.
- **Image Load Notifications:** Detection of DLL injection and reflective loading via `PsSetLoadImageNotifyRoutine`.

### 2. NexusService (User-Mode Service)
A persistent Windows service acting as the central intelligence hub:
- **ETW Orchestration:** Consumes and analyzes Event Tracing for Windows (ETW) streams for network activity, RPC calls, and advanced system events.
- **Behavioral Correlation Engine:** Correlates disparate system events (e.g., a suspicious DNS query followed by a `powershell.exe` execution and a registry modification) to identify complex attack patterns.
- **Policy Enforcement:** Communicates with the kernel driver via IOCTLs to enforce detection rules and automated remediation actions.

### 3. NexusEngine (Detection & Analytics)
A modular engine implementing:
- **Heuristic Pattern Matching:** Signature-less detection of known exploitation techniques (e.g., LOLBins, Process Hollowing).
- **Memory Forensic Analysis:** Real-time scanning of process memory for shellcode, RWX pages, and hidden modules.
- **Network Traffic Correlation:** Identifying C2 communication patterns and data exfiltration attempts.

## Forensic Capabilities
- **Event Journaling:** High-fidelity logging of system events in a tamper-resistant format.
- **Process Lineage Tracking:** Full visibility into parent-child process relationships and execution chains.
- **Snapshot Recovery:** Automated capture of forensic artifacts (memory dumps, suspicious files) upon threat detection.

## Technical Specifications
- **Core Standards:** C++17 (User-mode), C11 (Kernel-mode).
- **Minimum OS:** Windows 10 (Build 1809+) / Windows Server 2019.
- **Build System:** CMake + WDK (Windows Driver Kit).
- **Communication:** Secure IOCTL channel with ACL enforcement.

## Project Structure
```text
.
├── NexusEDR/
│   ├── common/         # Shared headers and data structures
│   ├── driver/         # Kernel-mode driver source (WDK)
│   ├── engine/         # Behavioral correlation and detection logic
│   ├── scanner/        # Memory and file forensic scanners
│   └── service/        # User-mode service and ETW orchestrator
├── tests/              # Integration and unit tests
└── build/              # Build artifacts (generated)
```

## Licensing
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
