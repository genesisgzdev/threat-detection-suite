# Threat Detection Suite (TDS)

High-fidelity Endpoint Detection and Response (EDR) core for Windows. Built on a zero-polling, event-driven architecture for kernel-mode interception and real-time forensic analysis.

## Technical Architecture

The system utilizes an **Inverted Call Model** to ensure zero-latency telemetry delivery from Ring 0 to Ring 3.

```mermaid
graph TD
    subgraph Kernel Space (Ring 0)
        A[Minifilter: File IO] -->|Queue| E[Event Dispatcher]
        B[WFP: Network Flow] -->|Queue| E
        C[ObCallbacks: Self-Protection] -->|Queue| E
        D[Registry Callbacks] -->|Queue| E
        E -->|Complete| F[Pending IRP Queue]
    end
    subgraph User Space (Ring 3)
        G[TDSService.exe] -->|IOCTL_GET_EVENT| F
        G -->|Process| H[Sequence Correlator]
        H -->|Alert| I[SOC Reporting]
        H -->|Action| J[IPS Manager: Block/Kill]
        G -->|Forensics| K[Memory Scanner / Dump]
    end
```

### Core Interception Modules

-   **Process & Thread Monitor**: Captures `CREATE_SUSPENDED` events and remote thread injections. Implements strict path validation for critical processes like LSASS.
-   **Network Shield (WFP)**: Native callouts for IPv4/v6 and UDP/DNS. Identifies C2 patterns and DGA activity without user-mode hooks.
-   **File Guard (Minifilter)**: Post-operation interception of IRPs to detect rapid entropy changes (Ransomware indicators).
-   **Self-Protection**: Uses `ObRegisterCallbacks` to strip dangerous access rights (`PROCESS_TERMINATE`, `PROCESS_VM_WRITE`) from handles targeting EDR components.

## Real-Time Engine Characteristics

-   **Zero-Polling**: The driver remains dormant until a kernel callback is triggered.
-   **Asynchronous IPC**: Uses pending IRPs to "push" events to the service immediately.
-   **Atomic Forensics**: Automatic memory dumping via `MiniDumpWriteDump` upon critical detection.

## Getting Started

### Prerequisites
- Windows 10/11 x64 (Test Signing Enabled)
- Visual Studio 2022 + WDK

### Build & Load
```powershell
cmake -B build
cmake --build build --config Release
sc create TDSDriver type= kernel binPath= C:\path\to\TDSDriver.sys
sc start TDSDriver
```

## Security Notice
For defensive research and educational purposes only. Zero simulated logic. Full native implementation.
