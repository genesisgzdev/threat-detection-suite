# Security Policy and Threat Model

## Threat Model
The Threat Detection Suite (TDS) assumes an attacker with local execution privileges in User-Mode (Ring 3), attempting to escalate to Kernel-Mode (Ring 0), exfiltrate data, or deploy fileless payloads.

### In-Scope Vulnerabilities
- **Direct Syscalls & API Unhooking**: Bypassing user-mode API hooks (
tdll.dll).
- **Memory Evasion**: NOP Sleds, Reflective DLL Loading, and Process Hollowing in MEM_PRIVATE space.
- **Ransomware / Wiper Mass I/O**: High-velocity file modifications and Volume Shadow Copy (VSS) deletion via ssadmin or wmic.
- **Covert Channels**: Exfiltration over ICMP payloads or oversized DNS (UDP 53) queries.

### Out-of-Scope Vulnerabilities
- **Bootkits / UEFI Rootkits**: TDS is initialized by the NT Kernel. It relies on Secure Boot and TPM measurements to guarantee the integrity of the early boot chain.
- **Physical Access Attacks**: Direct Memory Access (DMA) attacks via Thunderbolt/PCIe or cold boot attacks.

## Vulnerability Reporting
Submit findings involving Kernel Panics (BSOD), memory leaks, lock contention, or execution bypasses directly via GitHub Issues. Ensure any Proof-of-Concept (PoC) code targets isolated execution paths and limits loop counts to prevent denial of service during triage.
