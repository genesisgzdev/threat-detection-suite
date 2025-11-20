# Threat Detection Suite

## Overview

Threat Detection Suite is a comprehensive multi-vector malware detection framework designed for Windows systems. The suite implements advanced behavioral analysis, API monitoring, and kernel-level inspection techniques to identify sophisticated threats including rootkits, living-off-the-land (LOLBin) attacks, persistence mechanisms, and command-and-control communications.

## Technical Architecture

### Core Components

The framework implements a modular architecture consisting of:

- **Process Behavior Analyzer**: Real-time monitoring of process execution patterns with anomaly detection for suspicious DLL loading and injection techniques
- **API Hook Detector**: Memory integrity verification system that identifies API interception attempts through signature analysis and IAT manipulation detection
- **Memory Anomaly Scanner**: Deep memory inspection for executable code in non-standard regions, hollowing detection, and memory protection anomalies
- **Registry Monitor**: Comprehensive registry persistence detection across HKCU and HKLM hives with pattern-based threat identification
- **Network Connection Analyzer**: TCP connection monitoring with suspicious port detection and C2 communication pattern recognition
- **Persistence File Detector**: File system analysis for hidden/system attribute combinations and cryptographic signature matching
- **LOLBin Detector**: Command-line analysis for living-off-the-land binary abuse with risk scoring algorithms

### Performance Characteristics

- Multi-threaded scanning with thread-safe logging mechanisms
- Real-time threat correlation across detection modules
- Memory-efficient streaming for large-scale system analysis
- Critical section synchronization for concurrent operations
- Automatic privilege escalation verification
- Graceful shutdown handling with signal interception

## Features

### Detection Capabilities

**Process Behavior Analysis**
- Suspicious process execution pattern detection
- DLL injection identification through module enumeration
- Unusual module count anomaly detection (>100 DLLs)
- Non-standard DLL extension detection (.dat, .enc, .tmp)
- AMSI bypass attempt identification
- Process hollowing indicators
- Parent-child process relationship analysis

**API Interception Detection**
- Critical API hook identification (CreateProcess, WriteProcessMemory, VirtualAllocEx, etc.)
- Hook signature analysis for inline hooks
- JMP/CALL instruction pattern recognition
- Import Address Table (IAT) manipulation detection
- Prologue modification detection
- DLL injection pattern identification

**Memory Anomaly Detection**
- Executable memory region scanning
- Memory protection flag anomaly detection (PAGE_EXECUTE_READWRITE)
- Process hollowing detection through memory comparison
- Code injection pattern recognition
- Memory-mapped file analysis

**Registry Persistence Detection**
- AutoRun key enumeration (Run, RunOnce)
- WOW6432Node persistence detection
- Suspicious registry value pattern matching
- Service persistence identification
- Startup folder monitoring

**Network Threat Detection**
- Suspicious port connection monitoring (4444, 5555, 6666, 7777, 8888, etc.)
- C2 communication pattern recognition
- Private IP range connection anomalies
- High port number connection detection
- Process-to-connection correlation

**Persistence File Detection**
- HIDDEN+SYSTEM attribute combination identification
- Encryption signature analysis
- Anomalous file location detection (AppData, Temp, ProgramData)
- Cryptographic pattern matching
- Startup folder suspicious file analysis

**LOLBin (Living Off The Land) Detection**
- certutil.exe abuse detection (encoding, decoding, URL cache operations)
- PowerShell obfuscation identification
- WMI command-line analysis
- Encoded command detection (-enc, -encodedCommand)
- Hidden window execution monitoring
- Invoke-Expression (IEX) pattern detection
- Base64 string detection
- Download operation identification
- Risk scoring system with weighted threat indicators

### Security Features

- Administrator privilege requirement enforcement
- Thread-safe threat logging with critical sections
- Graceful shutdown handling (Ctrl+C, Ctrl+Break)
- Real-time threat severity classification (CRITICAL, HIGH, MEDIUM, INFO)
- Comprehensive IOC (Indicator of Compromise) tracking
- Timestamp-based threat correlation
- Process ID association for all detections

## Installation

### System Requirements

- Windows 10/11 or Windows Server 2016+
- Visual Studio 2019 or later with C++ compiler
- Administrator privileges required for execution
- Minimum 4GB RAM (8GB recommended)
- 50MB available disk space

### Compilation

```bash
# Using Visual Studio Developer Command Prompt
cl /EHsc /O2 ThreatDetectionSuitee.cpp /Fe:ThreatDetector.exe ^
   ws2_32.lib advapi32.lib shell32.lib psapi.lib iphlpapi.lib ntdll.lib

# Or using MSBuild
msbuild ThreatDetectionSuite.sln /p:Configuration=Release
```

### Dependencies

The following Windows libraries are automatically linked:
- `ws2_32.lib` - Winsock 2 for network operations
- `advapi32.lib` - Advanced Windows 32 Base API for registry and security
- `shell32.lib` - Shell API for file system operations
- `psapi.lib` - Process Status API for process enumeration
- `iphlpapi.lib` - IP Helper API for network connection analysis
- `ntdll.lib` - NT Layer DLL for low-level system access

## Usage

### Command Line Execution

```bash
# Run with administrator privileges
ThreatDetector.exe

# Output will display real-time detections:
# [CRITICAL] [PROCESS] Suspicious process detected
# [HIGH] [NETWORK] Suspicious port connection
# [CRITICAL] [HOOK] API hook detected
```

### Detection Output

The tool provides real-time console output with severity-based threat logging:

```
THREAT DETECTION SUITE v5.0

[*] Scanning process behavior
[*] Scanning for API hooks
[*] Scanning memory anomalies
[*] Scanning registry
[*] Scanning network connections
[*] Scanning persistence files
[*] Scanning Living-of-the-Land binaries

[CRITICAL] [LOLBIN] certutil.exe detected with suspicious parameters
[CRITICAL] [HOOK] CreateProcessA hook detected
[HIGH] [NETWORK] Suspicious connection to 192.168.1.100:4444
[CRITICAL] [PERSISTENCE] Hidden+System file detected: C:\ProgramData\audio.dat

THREAT ANALYSIS REPORT
Total threats detected: 42
Critical threats: 15

Detailed Log:
[CRITICAL] LOLBin abuse: certutil.exe with encoding parameters
[CRITICAL] API hook detected on WriteProcessMemory
[HIGH] Suspicious DLL loaded: unknown.dat
[CRITICAL] Hidden persistence file with encryption signature
```

### Threat Severity Levels

| Severity | Score | Description |
|----------|-------|-------------|
| **CRITICAL** | 80+ | Immediate action required - active threat indicators |
| **HIGH** | 50-79 | Significant risk - suspicious patterns detected |
| **MEDIUM** | 25-49 | Potential concern - anomalous behavior identified |
| **INFO** | 10-24 | Informational - baseline activity monitoring |

### Threat Categories

The suite classifies threats into 16 distinct categories:

- `PROCESS` - Process execution anomalies
- `DLL_INJECTION` - Dynamic library injection patterns
- `MEMORY` - Memory manipulation and code injection
- `FILE` - File system anomalies
- `REGISTRY` - Registry persistence mechanisms
- `NETWORK` - Network communication threats
- `PRIVILEGE_ESC` - Privilege escalation attempts
- `ANTI_ANALYSIS` - Anti-debugging/analysis techniques
- `CREDENTIALS` - Credential theft indicators
- `HOOK` - API hooking and interception
- `LOLBIN` - Living-off-the-land binary abuse
- `PERSISTENCE` - Persistence mechanism detection
- `C2` - Command and control communications
- `KERNEL` - Kernel-level manipulation
- `ROOTKIT` - Rootkit signatures
- `EVASION` - Evasion technique detection

## Detection Algorithms

### LOLBin Risk Scoring

The framework implements a weighted risk scoring system for LOLBin abuse detection:

```
Base Score = 0

certutil.exe patterns:
+ 30 points: -encode or -decode flags
+ 45 points: -urlcache or -download flags
+ 50 points: HTTP/HTTPS URL parameters

PowerShell patterns:
+ 45 points: -enc or -encodedCommand flags
+ 30 points: -NoProfile flag
+ 40 points: Hidden window execution
+ 50 points: IEX or Invoke-Expression
+ 60 points: DownloadString or FromBase64String

WMI patterns:
+ 50 points: process call commands

Threshold Classification:
≥75 = CRITICAL threat
≥50 = HIGH threat
<50 = Monitored (not logged)
```

### API Hook Detection

The suite examines the first 16 bytes of critical API functions for hook signatures:

```
Hook Signatures Detected:
- 0xEB (JMP short)
- 0xE9 (JMP near)
- 0x68 ... 0xC3 (PUSH + RET trampoline)
- 0x49 0xBB (MOV R11 trampoline)
- 0xFF 0x25 (JMP indirect)
- 0xFF 0x15 (CALL indirect)
```

Monitored APIs:
- CreateProcessA/W
- CreateRemoteThread
- WriteProcessMemory
- VirtualAllocEx
- VirtualProtect
- GetProcAddress
- LoadLibraryA/W
- SetWindowsHookExA/W

### Memory Anomaly Detection

Memory scanning focuses on:
- Executable regions outside standard module ranges
- PAGE_EXECUTE_READWRITE protection flags
- Code in heap/stack regions
- Process hollowing indicators
- Reflective DLL loading patterns

## Advanced Features

### Concurrent Threat Logging

Thread-safe logging implementation using Windows Critical Sections:

```cpp
// Thread-safe threat correlation
EnterCriticalSection(&global_threat_lock);
ThreatLog threat;
threat.threat_id = global_threat_counter++;
threat.severity = severity;
threat.category = category;
global_threat_log.push_back(threat);
LeaveCriticalSection(&global_threat_lock);
```

### Process Command Line Analysis

Low-level process parameter extraction via PEB (Process Environment Block) access:

```cpp
// Extract full command line including arguments
NtQueryInformationProcess() → PEB
PEB.ProcessParameters → RTL_USER_PROCESS_PARAMETERS
CommandLine.Buffer → Full command line string
```

### Network Connection Correlation

Process-to-network connection mapping:

```cpp
// TCP connection table enumeration
GetTcpTable2() → MIB_TCPTABLE2
For each connection:
  - Extract remote IP and port
  - Map to owning process ID (dwOwningPid)
  - Correlate with suspicious patterns
```

## Troubleshooting

### Common Issues

**Administrator Privilege Error**
```
[!] Administrator privileges required
[*] Please run this program as Administrator
```
**Solution**: Right-click executable → "Run as Administrator"

**Compilation Errors**

Missing Windows SDK:
```bash
# Install Windows SDK via Visual Studio Installer
# Or download standalone: https://developer.microsoft.com/windows/downloads/windows-sdk/
```

Linker errors for libraries:
```bash
# Ensure all required .lib files are specified
# Check Windows Kit installation path
```

**False Positives**

The suite may flag legitimate software in certain scenarios:
- Security software with kernel drivers
- Legitimate hooking frameworks (debugging tools)
- System utilities using PowerShell/certutil legitimately

Recommendation: Review context and validate against known-good software signatures.

### Debug Mode

Enable verbose output by modifying the source:

```cpp
// Add detailed logging in each scan function
printf("[DEBUG] Scanning process: %s (PID: %d)\n", entry.szExeFile, entry.th32ProcessID);
printf("[DEBUG] Risk score: %d\n", risk_score);
```

## Security Considerations

### Operational Security

- **Always run with administrator privileges** for comprehensive system access
- **Use in controlled environments** for testing and analysis
- **Validate detections** before taking remediation actions
- **Monitor system performance** during scanning operations
- **Review false positive patterns** in your environment

### Data Handling

- Threat logs stored in memory during execution
- No automatic persistence of detection data
- Results displayed in real-time console output
- Sensitive IOCs printed to stdout (redirect if needed)
- Clean shutdown ensures proper resource cleanup

### Responsible Use

This tool should only be used for:
- Authorized security assessments on owned systems
- Malware analysis in sandboxed environments
- Incident response and forensic investigations
- Security research with proper authorization
- Educational purposes in controlled settings

## Performance Optimization

### Optimization Techniques

- Critical section synchronization minimizes lock contention
- Snapshot-based process enumeration reduces overhead
- Targeted API monitoring (not comprehensive hooking)
- Memory-efficient string operations with bounded buffers
- Selective scanning based on threat indicators

### Benchmarks

| Operation | Average Time | Processes Scanned |
|-----------|--------------|-------------------|
| Process behavior scan | 2-3s | 100-150 processes |
| API hook detection | 1-2s | 11 critical APIs |
| Memory anomaly scan | 3-5s | All process memory regions |
| Registry scan | 1-2s | 3 key registry paths |
| Network connection scan | 1s | Active TCP connections |
| Persistence file scan | 2-4s | Common persistence locations |
| LOLBin detection | 2-3s | Active processes with cmdline analysis |
| **Total scan time** | **12-20s** | **Full system analysis** |

## Technical Implementation Details

### Architecture Decisions

**Why C++ with Windows API:**
- Direct system-level access for low-level detection
- Maximum performance for real-time monitoring
- No managed runtime overhead
- Native API access for kernel operations

**Modular Design:**
- Each detection module operates independently
- Threat correlation through centralized logging
- Easy extension for new detection techniques
- Minimal code coupling between modules

**Synchronization Strategy:**
- Critical sections for thread-safe logging
- Single-threaded scanning (sequential module execution)
- Future enhancement: Multi-threaded parallel scanning

### Code Quality

- Bounded string operations (strncpy_s, snprintf)
- Resource cleanup (CloseHandle, RegCloseKey)
- Memory leak prevention (malloc/free pairing)
- Null pointer checks before dereferencing
- Buffer overflow protection with size limits

## Legal Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. THE AUTHOR ASSUMES NO LIABILITY FOR MISUSE OR DAMAGES CAUSED BY THIS TOOL. USERS ARE SOLELY RESPONSIBLE FOR ENSURING COMPLIANCE WITH ALL APPLICABLE LAWS AND REGULATIONS IN THEIR JURISDICTION.

### Important Legal Notices

1. **Authorization Required**: Users must obtain explicit authorization before scanning any system. Unauthorized access to computer systems is illegal under various laws including the Computer Fraud and Abuse Act (CFAA) in the United States and similar legislation worldwide.

2. **Privacy Laws**: Collection and processing of system data must comply with applicable privacy laws including GDPR (European Union), CCPA (California), and other regional regulations.

3. **Ethical Guidelines**: This tool must not be used for:
   - Unauthorized system access or surveillance
   - Malicious activities of any kind
   - Privacy violations
   - Illegal operations

4. **No Warranty**: The developer provides no warranty regarding the accuracy, reliability, or completeness of threat detection results.

5. **Limitation of Liability**: In no event shall the developer be liable for any special, direct, indirect, or consequential damages arising from the use of this software.

### Compliance Requirements

Users are responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction, including but not limited to:
- Computer fraud and unauthorized access laws
- Data protection and privacy regulations
- Incident response and forensic investigation standards
- Industry-specific compliance requirements (PCI-DSS, HIPAA, etc.)

## Future Enhancements

### Planned Features

- **Multi-threaded Scanning**: Parallel module execution for faster analysis
- **Real-time Monitoring Mode**: Continuous background threat detection
- **Signature Database**: Expandable threat signature repository
- **Report Generation**: JSON/XML/HTML output formats
- **Configuration File Support**: Customizable detection parameters
- **Log File Persistence**: Optional threat log storage
- **Whitelist Management**: Known-good process/file exclusions
- **Driver-level Monitoring**: Kernel-mode detection capabilities
- **Network Capture**: PCAP-based traffic analysis
- **Machine Learning Integration**: AI-powered anomaly detection

### Research Areas

- Advanced evasion technique detection
- Hardware-assisted virtualization detection
- Firmware rootkit identification
- Container escape detection
- Supply chain attack indicators
- Advanced persistent threat (APT) signatures

## Support

For bug reports, feature requests, and security vulnerabilities, please use the issue tracker on the project repository.

**Security Vulnerabilities**: Please report security issues responsibly via email to avoid public disclosure before patching.

## Contributing

Contributions are welcome! Areas of interest:
- New detection algorithms
- Performance optimizations
- False positive reduction
- Documentation improvements
- Test case development
- Cross-platform compatibility (Linux/macOS via Wine analysis)

## Author

**Genesis**  
Security Researcher & Software Developer  
Contact: genzt.dev@pm.me

## License

MIT License - See LICENSE file for complete terms.

---

**Threat Detection Suite** - Advanced Multi-Vector Malware Detection for Windows Systems  
*Dedicated to building secure, privacy-respecting tools for the cybersecurity community*
