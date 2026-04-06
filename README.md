# Threat Detection Suite (TDS)
> **Advanced Event-Driven Endpoint Detection and Response (EDR) for Windows**

[![Security Status](https://img.shields.io/badge/Security-Snyk%20Certified-blueviolet?style=for-the-badge&logo=snyk)](https://app.snyk.io/org/genesisgzdev)
[![Kernel Mode](https://img.shields.io/badge/Kernel-WDM%20%7C%20WDF-blue?style=for-the-badge)](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)
[![License](https://img.shields.io/badge/License-Apache%202.0-red?style=for-the-badge)](LICENSE)
[![CI Status](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/security.yml/badge.svg)](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/security.yml)

---

## 🎯 Project Overview
Threat Detection Suite (TDS) is a high-performance, event-driven security ecosystem designed for deep system visibility and automated threat remediation. Unlike basic monitoring tools that rely on expensive polling (e.g., `psutil` or WMI queries), TDS utilizes **native Windows kernel callbacks** and **ETW (Event Tracing for Windows)** to provide real-time, low-overhead telemetry.

---

## 🏗 Key Architectural Pillars

### 1. TDS Kernel Engine (`TDSDriver.sys`)
The heart of the suite is a robust WDM driver that intercepts system activity at the lowest level:
- **Process/Thread Monitoring**: Uses `PsSetCreateProcessNotifyRoutineEx` and `PsSetCreateThreadNotifyRoutine` to capture execution lineage and detect remote thread injection.
- **Network Interception (WFP)**: Implements Windows Filtering Platform callouts to monitor IPv4/v6 and UDP/DNS traffic, identifying C2 beaconing and exfiltration.
- **File System Guard (Minifilter)**: Intercepts IRPs via a Filter Manager callback to detect ransomware-like behavior (mass renaming/deletion).
- **Self-Protection**: Leverages `ObRegisterCallbacks` to strip dangerous handle rights (`PROCESS_TERMINATE`, `PROCESS_VM_WRITE`) from unauthorized processes targeting the EDR.

### 2. Behavioral Correlation Engine
A stateful user-mode service that aggregates kernel telemetry to identify complex attack chains:
- **Early Bird Detection**: Correlates process creation in a suspended state with subsequent APC queuing.
- **Process Hollowing**: Cross-references memory `TimeDateStamp` with disk images and identifies anomalous RWX sections in `.text`.
- **DKOM Exposure**: Identifies hidden rootkit processes by cross-checking `NtQuerySystemInformation` against Win32 snapshots.

### 3. Automated Forensics (`ForensicManager`)
Upon detection of a **CRITICAL** threat, TDS automatically:
- Triggers a full process memory dump using `MiniDumpWriteDump` for offline analysis.
- Enriches IoCs (hashes/IPs) using the **Google Threat Intelligence (GTI)** bridge.
- Logs structured **JSONL** events ready for SIEM ingestion (Chronicle/Splunk).

---

## 🛠 Technical Specifications
- **Languages**: C11 (Kernel), C++17 (User-mode).
- **Inter-Process Communication**: Secured **Inverted Call Model** via pending IRPs and METHOD_BUFFERED IOCTLs.
- **Binary Security**: Compiled with `/GS`, `/guard:cf`, and `/DYNAMICBASE`; all sensitive kernel strings are obfuscated.
- **CI/CD**: Fully automated pipeline with **Snyk SAST** and **OSV-Scanner**.

---

## 🚦 Getting Started

### Prerequisites
- Windows 10/11 (x64).
- Visual Studio 2022+ with **WDK (Windows Driver Kit)**.
- Test Signing mode enabled (`bcdedit /set testsigning on`).

### Installation
```powershell
# Build the user-mode service
cmake -B build
cmake --build build --config Release

# Install the driver (Requires Admin)
sc create TDSDriver type= kernel binPath= C:\path\to\TDSDriver.sys
sc start TDSDriver
```

---

## 🗺 Roadmap
- [ ] Implement ELAM (Early Launch Anti-Malware) support.
- [ ] Add Kernel-mode stack walking for advanced ROP detection.
- [ ] Integration with Microsoft Threat Intelligence (MSTI) feeds.
- [ ] Real-time Registry Hive rollback.

---

## 📜 Legal Notice
This tool is for **defensive research and educational purposes only**. See [DISCLAIMER.md](DISCLAIMER.md) for full terms. All contributions are subject to the [Apache License 2.0](LICENSE).

---
*Technical integrity is not a feature; it's a foundation. Zero polling. Zero simulations.*
