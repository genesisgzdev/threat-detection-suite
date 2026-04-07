# Threat Detection Suite (TDS) - v5.0.0

Event-driven Endpoint Detection and Response (EDR) framework for Windows. This suite implements low-level kernel interception and high-fidelity user-mode analysis without relying on polling or expensive system-wide hooks.

## Table of Contents
1. [Technical Architecture Overview](#technical-architecture-overview)
2. [Kernel Interceptor (TDSDriver.sys)](#kernel-interceptor-tdsdriversys)
   - [Object Callbacks and Self-Protection](#object-callbacks-and-self-protection)
   - [Minifilter File System Guard](#minifilter-file-system-guard)
   - [Windows Filtering Platform (WFP) Integration](#windows-filtering-platform-wfp-integration)
3. [The Inverted Call Model (IPC)](#the-inverted-call-model-ipc)
4. [Detection Engine (TDSService.exe)](#detection-engine-tdsserviceexe)
   - [Event Correlation State Machine](#event-correlation-state-machine)
   - [Memory Forensics & VAD Parsing](#memory-forensics--vad-parsing)
5. [Operational Stability and Locking](#operational-stability-and-locking)
6. [Forensic Artifact Management](#forensic-artifact-management)
7. [Technical Specifications and Event Schemas](#technical-specifications-and-event-schemas)
8. [Build and Deployment Instructions](#build-and-deployment-instructions)
9. [Fuzzing and Quality Assurance](#fuzzing-and-quality-assurance)

## Technical Architecture Overview

TDS operates on a strict, event-driven tiered interception model. It bridges the `Ring 0` kernel space and `Ring 3` user space utilizing an asynchronous **Inverted Call Model**. This architectural decision ensures that the kernel driver pushes security telemetry to the user-mode service with minimal latency, avoiding the CPU overhead inherent in polling mechanisms.

## Kernel Interceptor (TDSDriver.sys)

The kernel module is a Windows Driver Model (WDM) driver combined with a registered Filter Manager (FltMgr) component.

### Object Callbacks and Self-Protection
The EDR enforces its integrity and protects critical system processes via `ObRegisterCallbacks`.
- **Registration**: The driver registers a `POB_PRE_OPERATION_CALLBACK` for both `PsProcessType` and `PsThreadType`.
- **Handle Stripping Logic**: When a process requests a handle, the pre-operation callback evaluates the target PID. If the target is the TDS Service (`TDSService.exe`) or the Local Security Authority (`lsass.exe`), the driver intercepts the `DesiredAccess` bitmask.
- **Enforcement**: It strips rights such as `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_SUSPEND_RESUME`, and `PROCESS_TERMINATE`. This neutralizes process injection and memory dumping without SSDT hooks.

### Minifilter File System Guard
Operating at altitude `385210`, the Minifilter inspects I/O Request Packets (IRPs) at the file system level.
- **Ransomware Heuristics**: Hooks `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, and `IRP_MJ_SET_INFORMATION`. It employs a post-operation callback on writes to calculate rolling entropy.
- **Dropper Detection**: Monitors the `FILE_DELETE_ON_CLOSE` disposition flag during file creation to identify intermediate dropper payloads.
- **Path Normalization**: Utilizes `FltGetFileNameInformation` with the `FLT_FILE_NAME_NORMALIZED` flag to resolve accurate file paths, bypassing 8.3 short names or symbolic links evasion.

### Windows Filtering Platform (WFP) Integration
Network telemetry is captured natively at the ALE layers.
- **Layer Registration**: Registers callouts at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` for connection-oriented traffic and `FWPM_LAYER_DATAGRAM_DATA_V4/V6` for UDP traffic.
- **Classification Context**: The `classifyFn` callback operates asynchronously. The connection tuple (Source IP, Target IP, Ports, PID) is routed to user-mode via the Inverted Call Model.
- **Teardown Safety**: Registered utilizing `FWPM_SESSION_FLAG_DYNAMIC`, ensuring all network filters are purged by the OS if the driver is unloaded.

## The Inverted Call Model (IPC)

User-mode to Kernel-mode IPC is handled via the Inverted Call Model.
- **Pending IRPs**: The `TDSService.exe` thread pool continuously sends `DeviceIoControl` requests containing the `IOCTL_TDS_GET_NEXT_EVENT` control code. The driver marks these IRPs as pending (`IoMarkIrpPending`) and queues them.
- **Asynchronous Completion**: When a kernel callback fires, it packages the telemetry, dequeues the oldest pending IRP, copies the data into the IRP's `SystemBuffer`, and calls `IoCompleteRequest`.
- **Cancel-Safe Queue (CSQ)**: Every pended IRP has a `CancelRoutine` assigned via `IoSetCancelRoutine`. If the service is terminated, the I/O Manager triggers the cancel routine, safely completing the IRP with `STATUS_CANCELLED`.

## Detection Engine (TDSService.exe)

### Event Correlation State Machine
- **Early Bird APC Detection**: The state machine tracks `CREATE_SUSPENDED` process creation events. If a remote thread queues an Asynchronous Procedure Call (APC) to this suspended thread before a `ResumeThread` event, the correlator flags it as an Early Bird injection sequence.
- **Time-Window Buffering**: Events are held in an ordered, timestamped buffer (`std::map<uint64_t, Event>`) to handle latency differences between ETW flushes and ICM telemetry.

### Memory Forensics & VAD Parsing
When the Correlator triggers a high-severity alert, the Memory Scanner engages.
- **Reflective Loading Detection**: It uses `NtQueryVirtualMemory` to parse the Virtual Address Descriptor (VAD) tree of the target process, searching for `MEM_PRIVATE` and `PAGE_EXECUTE_READWRITE` regions containing `MZ`/`PE` headers not backed by a physical file.

## Operational Stability and Locking

- **Spinlock Hierarchy**: The kernel driver enforces a strict locking order. `g_IrpQueueLock` is acquired before `g_EventQueueLock`. Both utilize `KeAcquireSpinLock` / `KeReleaseSpinLock`, elevating the IRQL to `DISPATCH_LEVEL`.
- **Backpressure Mechanism**: An `EVENT_QUEUE_LIMIT` (5000 items) is enforced. If the kernel queue fills, subsequent non-critical events are dropped, preventing NonPagedPool exhaustion.

## Forensic Artifact Management

- **Automated Evidence Collection**: Upon confirming a threat, the engine invokes `MiniDumpWriteDump` loaded from `dbghelp.dll`. It uses the `MiniDumpWithFullMemory` flag to capture the process address space, persisting the `.dmp` file to a secured directory for subsequent reverse engineering.

## Build and Deployment Instructions

### Prerequisites
- Windows 10/11 (x64)
- Visual Studio 2022 with "Desktop development with C++" and "Windows Driver Kit"
- CMake 3.20+

### Compilation
The project supports MSVC `cl.exe` native compilation or CMake orchestration.
```powershell
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

### Installation and Loading
Ensure the target machine has Test Signing enabled (`bcdedit /set testsigning on`) or the driver is signed with a valid EV certificate.
```powershell
# Create the kernel service
sc.exe create TDSDriver type= kernel binPath= "C:\bin\TDSDriver.sys"
# Load the kernel component
sc.exe start TDSDriver
# Launch the user-mode correlator
net start TDSService
```

## Fuzzing and Quality Assurance
The repository has been audited by OSV-Scanner and Snyk SAST pipelines, ensuring clean dependencies and strict static analysis compliance.
