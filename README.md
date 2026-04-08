# Threat Detection Suite (TDS) v5.6.5

## Executive Summary
Threat Detection Suite is a production-grade, bare-metal Endpoint Detection and Response (EDR) platform designed for Windows 10/11. Operating at Ring 0, TDS provides deterministic interception of advanced persistent threats (APTs), ransomware, and stealth rootkits using a zero-allocation, high-performance kernel architecture.

## Security Architecture & Kernel Internals

### 1. WFP Professional Sublayering (Weight 0xFFFF)
The network filtering engine leverages the Windows Filtering Platform (WFP) to inspect IPv4 and IPv6 streams and datagrams. To ensure our callouts evaluate packets prior to third-party consumer firewalls, a dedicated WFP sublayer (`TDS_SUBLAYER_GUID`) is registered.
* **Maximum Weighting:** The sublayer is assigned a weight of `0xFFFF`, the highest non-OS weight, guaranteeing authoritative traffic interception.
* **Loopback Exclusion & Fast-Path:** Standard rules enforce fast-path exemptions for local loopback traffic to minimize overhead on inter-process communications (IPC), while strictly auditing external egress/ingress (e.g., dropping DNS amplification attempts where UDP port 53 packets exceed 512 bytes).

### 2. LSASS Protection & Tamper Resistance
TDS provides robust, spoof-resistant tamper protection for critical system processes (like LSASS) and its own user-mode orchestrator, mitigating credential dumping and termination attempts.
* **Cryptographic Identity Verification:** The `IsLsass` validation routine strictly utilizes `PsGetProcessSignatureLevel()`. It validates that the target process holds a minimum Microsoft signature level (`>= 7`) *prior* to falling back on string-based path matching. This neutralizes trivial process-name spoofing.
* **Object Callbacks (`ObRegisterCallbacks`):** Within the `TDSPreCallback` routine, unauthorized handle requests asking for `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_SUSPEND_RESUME`, or `PROCESS_CREATE_THREAD` against protected processes have those flags dynamically stripped from their `DesiredAccess` mask.

### 3. Zero-Allocation Hot Paths (`NPAGED_LOOKASIDE_LIST`)
To guarantee deterministic execution times and prevent system-wide lock contention on the Non-Paged Pool (NPP), the driver employs pre-allocated Lookaside Lists for asynchronous event queuing.
* **Implementation:** `ExInitializeNPagedLookasideList` initializes a fixed-size event buffer pool during `DriverEntry`.
* **O(1) Telemetry:** High-frequency routines dynamically acquire event buffers via `ExAllocateFromNpagedLookasideList`. This guarantees constant-time allocation complexity, ensuring system stability even under extreme I/O stress or malware-induced event storms.

### 4. Reentrancy Prevention
Minifilter deadlocks—where an EDR intercepts its own file system actions, triggering an infinite loop of callbacks—are mitigated using strict requestor-awareness in the IRP dispatch routines.
* **Implementation:** Within the pre-operation callback (`TDSPreWriteCallback`), the driver invokes `FltGetRequestorProcess()` to accurately identify the originating `PEPROCESS`.

### 5. Anti-Ghosting & YARA Integration
The suite combines kernel-mode synchronization interception with user-mode advanced pattern matching to defeat complex evasions like reflective loading and process hollowing.
* **Anti-Ghosting:** Defeats "Ghosting" techniques by monitoring section synchronization operations and tracking process hollowing anomalies.
* **YARA Memory Engine:** The `MemoryScanner` integrates the YARA C-API (`libyara`) directly into the user-mode analysis service. It traverses the virtual address space of target processes (`MEM_PRIVATE`) for high-fidelity, real-time detection of fileless memory implants.

## CI/CD Pipeline & Code Quality
* **SARIF Snyk Integration:** The security pipeline runs deep Software Composition Analysis (SCA) against our dependency trees using Snyk. It strictly outputs a `snyk.sarif` report that is automatically ingested by GitHub Advanced Security.
* **Vulnerability Scanning:** The pipeline supplements Snyk with Google's `OSV-Scanner` for an additional layer of recursive open-source vulnerability detection.