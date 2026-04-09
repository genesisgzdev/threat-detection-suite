### Kernel Architecture
* Zero-allocation memory management via Lookaside Lists (NPAGED_LOOKASIDE_LIST).
* WFP Professional Sublayer (0xFFFF weight) with loopback exclusion.
* Signature-level LSASS protection (PsGetProcessSignatureLevel).
* Reentrancy prevention in Minifilter callbacks.
* Structured Exception Handling (SEH) for fuzzing survival.

### Userland Heuristics
* YARA engine integration (MEM_PRIVATE) to detect Direct Syscalls and NOP Sleds.
* ETW-Ti Collector for APC Early Bird Injection telemetry.
* Real-time SOC bot automation (Python).
