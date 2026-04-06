# Threat Detection Suite (TDS)
> **High-Performance, 100% Event-Driven EDR Core for Windows**

[![Kernel Architecture](https://img.shields.io/badge/Architecture-100%25%20Event--Driven-green?style=for-the-badge)](CONTRIBUTING.md)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge)](SECURITY.md)

TDS is an industrial-grade security framework designed to provide deep system visibility and automated threat remediation without the overhead of legacy polling mechanisms. By operating at the kernel level, TDS captures system events at their source, ensuring zero-latency telemetry and tamper-resistant monitoring.

---

## 🏗 Deep Technical Architecture

### 1. Zero-Polling Kernel Engine
Unlike traditional security tools that query process lists or file states every few seconds (polling), TDS is built on a **Push-Based Architecture**. It remains dormant until the Windows kernel triggers a registered callback, ensuring minimal CPU impact and eliminating the "blind spots" inherent in polling.

### 2. Network Interception (WFP Callouts)
TDS implements **Windows Filtering Platform (WFP)** callout drivers to intercept network traffic at the L3/L4 layers.
- **Deep Packet Inspection (DPI)**: Monitors IPv4/v6, TCP, and UDP traffic in real-time.
- **C2 Mitigation**: Identifies and blocks unauthorized beaconing by analyzing flow patterns before packets leave the network stack.
- **DNS Monitoring**: Intercepts `FWPM_LAYER_DATAGRAM_DATA_V4` to detect DGA (Domain Generation Algorithm) activity.

### 3. File System Guard (Minifilter)
The file system protection layer uses a **Filter Manager** minifilter driver.
- **Pre-Operation Interception**: Intercepts `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`, and `IRP_MJ_CREATE` requests.
- **Ransomware Protection**: Detects rapid, multi-file encryption patterns and halts the responsible process before significant data loss occurs.
- **Altitudes**: Operates at high-priority altitudes to ensure interception before malicious filter drivers.

### 4. Advanced Telemetry (ETW-Ti)
TDS leverages the **Event Tracing for Windows - Threat Intelligence (ETW-Ti)** provider to detect sophisticated in-memory attacks that standard callbacks might miss:
- **Injection Detection**: Monitors `KiSystemCall64` and memory allocation patterns to identify `VirtualAllocEx` / `WriteProcessMemory` chains used in Process Hollowing.
- **Token Manipulation**: Tracks security token changes to detect Privilege Escalation.
- **Module Loads**: Real-time tracking of DLL loads to identify sideloading and proxying.

---

## 🛡️ Core Security Features
- **Inverted Call Model**: A robust IPC mechanism where the user-mode engine waits on pending IRPs from the kernel, enabling the driver to "push" data to user-mode with zero delay.
- **Self-Protection (ObRegisterCallbacks)**: TDS protects its own process and service by stripping `PROCESS_TERMINATE` and `PROCESS_VM_WRITE` rights from any external process handle.
- **Forensic Pipeline**: Every detection triggers an automated forensic sequence, generating structured **JSONL** events enriched with **Google Threat Intelligence** data.

---

## 🚀 Deployment & Engineering

### Technical Stack
- **User-Mode**: C++17 (RAII, Modern STL).
- **Kernel-Mode**: C11 (WDK, KMDF).
- **Build System**: CMake with custom WDK integration.

### Getting Started
```powershell
# Prerequisites: Windows 10/11 x64, Visual Studio 2022, WDK.
# 1. Enable Test Signing
bcdedit /set testsigning on

# 2. Build the Suite
cmake -B build
cmake --build build --config Release

# 3. Load the Engine
sc create TDSDriver type= kernel binPath= C:\bin\TDSDriver.sys
sc start TDSDriver
```

---

## 📜 Legal & Ethical Notice
This project is for **defensive security research and educational use only**. Unauthorized use against systems you do not own is strictly prohibited. See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

*Defending the kernel, one callback at a time.*
