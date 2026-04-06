# Threat Detection Suite (TDS)

Advanced Endpoint Detection and Response (EDR) suite for Windows environments. TDS provides high-fidelity kernel-mode interception and user-mode forensic analysis capabilities.

## Architecture

The system is composed of two primary layers:

### 1. Kernel Interceptor (TDSDriver.sys)
A Ring 0 driver implementing multiple interception mechanisms:
- **Minifilter Driver**: Intercepts file I/O operations to detect ransomware patterns and unauthorized file access.
- **WFP (Windows Filtering Platform)**: Monitors network connections (IPv4/v6/UDP) to identify C2 beacons and malicious data exfiltration.
- **Object Callbacks**: Protects critical system processes (like LSASS) and the EDR service itself from termination and manipulation.
- **Registry Callbacks**: Monitors and blocks unauthorized persistence attempts in the Windows Registry.

### 2. Detection Engine (TDSService.exe)
A native Windows Service that orchestrates telemetry processing:
- **Sequence Correlator**: Links discrete kernel events to identify complex attack chains such as Process Hollowing and Early Bird APC Injection.
- **Memory Scanner**: Performs architecture-agnostic PE header analysis and scans for reflective loading in private memory regions.
- **Forensic Manager**: Automatically generates process memory dumps for critical detections using standard Windows APIs.

## Security and Integrity

- **Zero Dependency Mindset**: Core detection logic uses native Windows APIs to ensure maximum performance and minimum footprint.
- **Self-Protection**: The EDR process and its threads are shielded at the kernel level against unauthorized access and termination.
- **Standardized Telemetry**: Event logs are generated in structured JSONL format, prepared for integration with SOC platforms like Google SecOps (Chronicle).

## Disclaimer

This software is provided for research and security auditing purposes. Ensure proper authorization before deployment in production environments.
