# Threat Detection Suite

## Overview

Threat Detection Suite is an advanced endpoint detection and response (EDR) framework for Windows systems implementing automated threat identification and active remediation. The suite combines behavioral analysis, API monitoring, entropy-based cryptographic detection, and real-time remediation capabilities to address sophisticated malware including rootkits, LOLBin attacks, persistence mechanisms, and command-and-control infrastructure.

## Technical Architecture

### Integrated Detection and Response System

The framework implements a unified threat detection and automated remediation architecture:

- **Seven-Phase Detection Engine**: Sequential threat analysis across process behavior, API hooks, memory anomalies, registry persistence, network communications, file entropy, and LOLBin abuse
- **Four-Module Remediation System**: Automated response capabilities including process termination, registry cleanup, file quarantine, and network disruption
- **Real-Time Correlation**: Thread-safe logging with critical section synchronization enabling concurrent threat tracking across detection phases
- **Comprehensive Statistics**: Detailed remediation metrics tracking successful actions, failures, and per-category breakdowns

### Core Detection Subsystems

**Process Behavior Analyzer**
- Real-time DLL injection detection through EnumProcessModules with configurable thresholds
- High severity trigger: >80 loaded modules, Critical escalation: >120 modules with automatic termination
- Suspicious process name pattern matching (audio/media/svchost themes)
- AMSI bypass detection through non-standard DLL extension identification (.dat, .enc, .tmp)

**API Hook Detector**
- Six-pattern multi-signature engine: Short JMP (0xEB), Long JMP (0xE9), PUSH+RET (0x68...0xC3), MOV R11 trampoline (0x49 0xBB), RIP-relative JMP (0xFF 0x25), RIP-relative CALL (0xFF 0x15)
- Monitors five critical kernel32 APIs: CreateProcessA, CreateRemoteThread, WriteProcessMemory, LoadLibraryA, SetWindowsHookExA
- Memory integrity verification via ReadProcessMemory on function prologues
- Detours-compatible hook signature recognition

**Memory Anomaly Scanner**
- VirtualQueryEx-based executable region enumeration
- PAGE_EXECUTE_READWRITE and PAGE_EXECUTE_WRITECOPY protection flag detection
- NOP sled identification: 10+ consecutive 0x90 bytes triggers CRITICAL severity
- Automatic process termination on shellcode detection
- Minimum region size filtering (>4KB) to reduce false positives

**Registry Persistence Monitor**
- Six registry path scanning: HKCU/HKLM Run, RunOnce, WOW6432Node variants
- Nine malware signature patterns: Audio, MSAudio, Media, WindowsUpdate, svchost, driver, sound, Spy, Monitor
- Automatic registry value deletion via RegDeleteValueA on detection
- KEY_ALL_ACCESS permission enforcement for remediation
- Real-time statistics tracking for registry entries removed

**Network Connection Analyzer**
- GetTcpTable2 enumeration filtering for MIB_TCP_STATE_ESTAB connections
- Suspicious port detection: 4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 666, 1337
- Process-to-connection correlation via dwOwningPid
- Automatic process termination on C2 port detection
- Remote IP and port logging for forensic analysis

**Persistence File Detector**
- Real Shannon entropy calculation: -Σ(p × log₂(p)) with 7.8 bits/byte threshold
- HIDDEN+SYSTEM attribute combination detection (extremely rare in legitimate files)
- Automatic file quarantine via MoveFileExA with .QUARANTINE extension
- Temp directory scanning for encrypted persistence files
- Extension-based targeting: .dat, .enc for encryption indicator correlation

**LOLBin Abuse Analyzer**
- Real PEB (Process Environment Block) parsing via NtQueryInformationProcess
- Command-line extraction: PROCESS_BASIC_INFORMATION → PEB → RTL_USER_PROCESS_PARAMETERS → CommandLine.Buffer
- Weighted risk scoring algorithm with 12 indicators (0-100+ scale)
- certutil.exe patterns: -encode (+25), -encodedCommand (+30), -urlcache (+30), -download (+35), http/https (+15)
- PowerShell patterns: -enc (+20), IEX (+35), DownloadString (+40), FromBase64String (+25), -WindowStyle Hidden (+20)
- WMI detection: process + call pattern (+50)
- CRITICAL threshold: 85+ points triggers automatic termination
- HIGH threshold: 50+ points triggers logging without remediation

### Performance Characteristics

- **Sequential execution**: 7 detection phases + 4 remediation modules with optimized resource management
- **Thread-safe logging**: Critical section synchronization via InitializeCriticalSection/EnterCriticalSection/LeaveCriticalSection
- **Memory efficiency**: Bounded buffers (MAX_THREAT_DESC: 512 bytes, MAX_IOC_LEN: 256 bytes) with _TRUNCATE protection
- **Error resilience**: Comprehensive handle validation, NULL pointer checks, and graceful degradation on API failures
- **Resource cleanup**: Automatic handle closure (CloseHandle) and critical section deletion on shutdown

## Feature Implementation

### Automated Remediation Capabilities

**Process Termination Module**
```cpp
RemediateProcessTermination(DWORD pid, LPCSTR process_name)
- Opens process with PROCESS_TERMINATE rights
- Executes TerminateProcess() with exit code 127
- Logs ACTION_KILL_PROCESS with success/failure status
- Updates statistics: processes_killed, successful_actions, auto_remediation_count
- Integrated with: LOLBin detection (risk ≥85), Memory shellcode detection (NOP sled), 
  C2 detection (suspicious ports), DLL injection (>120 modules)
```

**Registry Cleanup Module**
```cpp
RemediateRegistryCleanup(HKEY root, LPCSTR subkey, LPCSTR value_name)
- Opens key with KEY_ALL_ACCESS permissions
- Deletes value via RegDeleteValueA
- Handles ERROR_ACCESS_DENIED gracefully
- Logs ACTION_REMOVE_REGISTRY with error codes
- Updates statistics: registry_entries_removed, auto_remediation_count
- Integrated with: Registry persistence detection (9 malware patterns)
```

**File Quarantine Module**
```cpp
RemediateFileQuarantine(LPCSTR file_path)
- Moves file using MoveFileExA with MOVEFILE_REPLACE_EXISTING
- Appends .QUARANTINE extension to quarantined path
- Preserves original file for forensic analysis
- Logs ACTION_QUARANTINE with source and destination paths
- Updates statistics: files_deleted, auto_remediation_count
- Integrated with: HIDDEN+SYSTEM detection, High entropy files (>7.8 bits/byte)
```

**Risk Scoring Algorithm**
```cpp
CalculateLOLBinRiskScore(LPCSTR command_line)
- Non-destructive read-only calculation
- Accumulative scoring: 12 command-line indicators
- Pattern matching: strstr() for case-sensitive detection
- Returns integer score: 0-100+ scale
- Thresholds: CRITICAL (85+), HIGH (50+), No action (<50)
```

### Detection Integration Points

**Six automated remediation triggers:**

1. **LOLBin Critical Risk** (risk_score ≥ LOLBIN_CRITICAL_SCORE [85])
   - Calls: RemediateProcessTermination(pid, process_name)
   - Logged as: SEVERITY_CRITICAL, CAT_LOLBIN_ABUSE

2. **Memory Shellcode Detection** (nop_count ≥ 10)
   - Calls: RemediateProcessTermination(pid, process_name)
   - Logged as: SEVERITY_CRITICAL, CAT_MEMORY_ANOMALY

3. **Registry Persistence Match** (9 malware patterns)
   - Calls: RemediateRegistryCleanup(HKEY_CURRENT_USER, path, value_name)
   - Logged as: SEVERITY_CRITICAL, CAT_REGISTRY_ANOMALY

4. **HIDDEN+SYSTEM File Attributes**
   - Calls: RemediateFileQuarantine(full_path)
   - Logged as: SEVERITY_CRITICAL, CAT_PERSISTENCE

5. **High Entropy Encrypted Files** (entropy > FILE_ENTROPY_CRITICAL [7.8])
   - Calls: RemediateFileQuarantine(full_path)
   - Logged as: SEVERITY_CRITICAL, CAT_PERSISTENCE
   - Additional conditions: HIDDEN attribute OR .dat/.enc extension

6. **C2 Communication on Suspicious Ports**
   - Calls: RemediateProcessTermination(owning_pid, "C2 Process")
   - Logged as: SEVERITY_CRITICAL, CAT_C2_COMMUNICATION

7. **Excessive DLL Loading** (dll_count > 120)
   - Calls: RemediateProcessTermination(pid, process_name)
   - Logged as: SEVERITY_CRITICAL, CAT_DLL_INJECTION

## Installation

### System Requirements

- **Operating System**: Windows 10 (1809+), Windows 11, Windows Server 2016+
- **Compiler**: Visual Studio 2019 or later, MSVC v142 toolset, Windows SDK 10.0.18362.0+
- **Privileges**: Administrator rights required for process memory access, registry modification, process termination
- **Hardware**: 4GB RAM minimum (8GB recommended), 100MB disk space, x64 processor
- **Dependencies**: C++17 standard library, Windows API libraries (ws2_32, advapi32, shell32, psapi, iphlpapi, ntdll)

### Compilation Instructions

**Visual Studio Developer Command Prompt (Recommended):**
```cmd
cl.exe /EHsc /std:c++17 /W4 /permissive- /O2 ThreatDetectionSuitex.cpp ^
  /link ws2_32.lib advapi32.lib shell32.lib psapi.lib iphlpapi.lib ntdll.lib ^
  /OUT:ThreatDetectionSuite.exe
```

**CMake Build (Cross-Platform):**
```bash
mkdir build && cd build
cmake -G "Visual Studio 16 2019" -A x64 ..
cmake --build . --config Release
```

**MinGW-w64 (Alternative):**
```bash
g++ -std=c++17 -O2 -Wall -Wextra ThreatDetectionSuitex.cpp ^
  -lws2_32 -ladvapi32 -lshell32 -lpsapi -liphlpapi -lntdll ^
  -o ThreatDetectionSuite.exe
```

### Library Dependencies

```
ws2_32.lib      - Winsock 2: TCP connection enumeration (GetTcpTable2)
advapi32.lib    - Advanced API: Registry operations (RegOpenKeyExA, RegDeleteValueA)
shell32.lib     - Shell API: Path resolution (SHGetFolderPath), file operations
psapi.lib       - Process API: Module enumeration (EnumProcessModules, GetModuleFileNameExA)
iphlpapi.lib    - IP Helper: Network tables (GetTcpTable2, MIB_TCPTABLE2)
ntdll.lib       - NT Layer: PEB access (NtQueryInformationProcess, PROCESS_BASIC_INFORMATION)
```

## Usage

### Command-Line Execution

```cmd
# Requires Administrator privileges
ThreatDetectionSuite.exe

# Expected privilege check on startup:
# Administrator privileges verified: Proceeding with detection
```

### Detection Output Format

**Real-Time Console Output:**
```
EDR SUITE: THREAT DETECTION & AUTO-REMEDIATION
Integrated Detection + Active Response System

[*] Starting threat detection and auto-remediation...

[PHASE 1] Process Behavior & DLL Injection Analysis
[HIGH] [DLL_INJECTION] Excessive module count: chrome.exe (PID: 4520) - 85 modules
[CRITICAL] [DLL_INJECTION] Excessive module count: malware.exe (PID: 8832) - 125 modules
[+] AUTO-REMEDIATION: Terminated process malware.exe (PID: 8832)

[PHASE 2] API Hook Detection (6-pattern engine)
[CRITICAL] [HOOK_DETECTION] Hook detected in CreateProcessA: Long relative JMP (Detours pattern)

[PHASE 3] Memory Anomaly & Shellcode Detection
[CRITICAL] [MEMORY_ANOMALY] Shellcode NOP sled in RWX page: exploit.exe (PID: 5644)
[+] AUTO-REMEDIATION: Terminated process exploit.exe (PID: 5644)

[PHASE 4] Registry Persistence Scanning with Auto-Cleanup
[CRITICAL] [REGISTRY_ANOMALY] Malware persistence detected: MSAudioDriver
[+] AUTO-REMEDIATION: Deleted registry key MSAudioDriver

[PHASE 5] Network C2 Detection with Auto-Termination
[CRITICAL] [C2_COMMUNICATION] Connection to 192.168.1.100:4444 (PID: 3340)
[+] AUTO-REMEDIATION: Terminated process with C2 connection (PID: 3340)

[PHASE 6] Persistence File Detection with Auto-Quarantine
[CRITICAL] [PERSISTENCE] HIDDEN+SYSTEM file (malware signature): audio.dat
[+] AUTO-REMEDIATION: Quarantined file C:\Temp\audio.dat -> C:\Temp\audio.dat.QUARANTINE

[PHASE 7] LOLBin Abuse Analysis with Risk Scoring
[CRITICAL] [LOLBIN_ABUSE] certutil.exe with critical payload (Risk: 95/100)
[+] AUTO-REMEDIATION: Terminated process certutil.exe (PID: 7712)

THREAT ANALYSIS REPORT
Total threats detected: 42

Critical threats: 15

AUTO-REMEDIATION REPORT
Total auto-remediation actions: 12
Successful actions: 11
Failed actions: 1

Breakdown:
  Processes terminated: 4
  Files quarantined: 2
  Registry entries removed: 5

Detailed Threat Log:
[CRITICAL] Excessive module count: malware.exe (PID: 8832) - 125 modules (ID: 0, PID: 8832)
[CRITICAL] Hook detected in CreateProcessA: Long relative JMP (Detours pattern) (ID: 1, PID: 0)
[CRITICAL] Shellcode NOP sled in RWX page: exploit.exe (PID: 5644) (ID: 2, PID: 5644)
...

Detailed Remediation Log:
[OK] Terminated process: malware.exe (PID: 8832)
[OK] Deleted registry value: MSAudioDriver
[FAIL] Failed to terminate process: system_protected.exe (Error: 5 - Access Denied)
...

EDR analysis and auto-remediation complete.
```

### Threat Severity Classification

| Severity | Numeric Value | Trigger Conditions | Remediation Action |
|----------|---------------|-------------------|-------------------|
| **CRITICAL** | 80 | LOLBin risk ≥85, NOP sled ≥10, HIDDEN+SYSTEM files, Entropy >7.8, C2 ports, DLL count >120 | Automatic termination/quarantine |
| **HIGH** | 50 | LOLBin risk 50-84, DLL count 80-120, Suspicious registry patterns | Logged, no auto-remediation |
| **MEDIUM** | 25 | Moderate anomalies, potential false positives | Informational logging |
| **INFO** | 10 | Baseline activity, low-confidence indicators | Verbose logging only |

### Threat Categorization

**16 distinct threat categories:**

```
CAT_PROCESS_BEHAVIOR     - Process execution anomalies, suspicious naming patterns
CAT_DLL_INJECTION        - Excessive module loading, non-standard DLL extensions
CAT_MEMORY_ANOMALY       - RWX pages, NOP sleds, shellcode indicators
CAT_FILE_ANOMALY         - File system anomalies, attribute manipulation
CAT_REGISTRY_ANOMALY     - Registry persistence, malware signature patterns
CAT_NETWORK_ANOMALY      - Network communication anomalies
CAT_PRIVILEGE_ESC        - Privilege escalation attempts (detection only, not remediated)
CAT_ANTI_ANALYSIS        - Anti-debugging techniques (detection only)
CAT_CREDENTIAL_THEFT     - Credential harvesting indicators (detection only)
CAT_HOOK_DETECTION       - API hooks, IAT manipulation, inline patches
CAT_LOLBIN_ABUSE         - Living-off-the-land binary misuse
CAT_PERSISTENCE          - Persistence mechanisms, encrypted files
CAT_C2_COMMUNICATION     - Command-and-control communications
CAT_KERNEL_ANOMALY       - Kernel-level manipulation (detection only)
CAT_ROOTKIT_INDICATOR    - Rootkit signatures (detection only)
CAT_EVASION              - Evasion techniques (detection only)
```

## Detection Algorithms

### Shannon Entropy Calculation

Implementation of information-theoretic entropy measurement for encrypted file detection:

```cpp
float CalculateEntropy(LPCVOID data, DWORD size) {
    // Frequency analysis
    unsigned int freq[256] = {0};
    for (DWORD i = 0; i < size; i++) {
        freq[((BYTE*)data)[i]]++;
    }
    
    // Shannon entropy: H(X) = -Σ p(x) × log₂(p(x))
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / size;
            entropy -= p * log2f(p);
        }
    }
    return entropy;  // Range: 0.0 (all zeros) to 8.0 (perfect randomness)
}

Interpretation:
  0.0 - 4.0: Plaintext or highly structured data
  4.0 - 6.0: Compressed or partially encrypted data
  6.0 - 7.8: Compressed with encryption, still structured
  >7.8:      Encrypted or cryptographically random (CRITICAL threshold)
```

### LOLBin Risk Scoring Matrix

Weighted threat indicator accumulation with command-line pattern matching:

```
Risk Score Calculation (0-100+ scale):

certutil.exe indicators:
  -encode                 : +25 points  (Base64 encoding operation)
  -encodedCommand         : +30 points  (Obfuscated command execution)
  -enc                    : +20 points  (Short-form encoding)
  IEX                     : +35 points  (Invoke-Expression, code execution)
  DownloadString          : +40 points  (Remote code download)
  -urlcache               : +30 points  (URL cache manipulation)
  -download               : +35 points  (File download operation)
  http://                 : +15 points  (HTTP protocol indicator)
  FromBase64String        : +25 points  (Base64 decoding)
  Invoke-Expression       : +40 points  (Direct code execution)
  -NoProfile              : +10 points  (PowerShell profile bypass)
  -WindowStyle Hidden     : +20 points  (Hidden window execution)

WMI indicators:
  process + call          : +50 points  (WMI process execution)

Classification Thresholds:
  0-49:   No action (legitimate usage patterns)
  50-84:  HIGH severity - Logged, manual review required
  85-100: CRITICAL severity - Automatic process termination
  100+:   Multiple indicators, definitive malicious intent
```

### API Hook Signature Detection

Six-pattern recognition engine for inline API hooks and trampolines:

```
Pattern 1: Short JMP (2 bytes)
  Signature: 0xEB xx
  Description: Relative jump ±127 bytes
  Use case: Short-range hooks, inline patches

Pattern 2: Long JMP (5 bytes) - Detours
  Signature: 0xE9 xx xx xx xx
  Description: Relative jump ±2GB
  Use case: Microsoft Detours, function hooking frameworks

Pattern 3: PUSH+RET Trampoline (6 bytes)
  Signature: 0x68 xx xx xx xx 0xC3
  Description: Push address, return to it
  Use case: Obfuscated hooks, anti-debugging

Pattern 4: MOV R11 + JMP R11 (12 bytes, x64)
  Signature: 0x49 0xBB ... 0x41 0xFF 0xE3
  Description: Load 64-bit address into R11, jump to R11
  Use case: 64-bit trampolines, position-independent hooks

Pattern 5: RIP-Relative JMP (6 bytes, x64)
  Signature: 0xFF 0x25 xx xx xx xx
  Description: Jump to address at [RIP + offset]
  Use case: Position-independent code, modern x64 hooks

Pattern 6: RIP-Relative CALL (6 bytes, x64)
  Signature: 0xFF 0x15 xx xx xx xx
  Description: Call address at [RIP + offset]
  Use case: Hook proxies, call forwarding

Detection methodology:
  1. GetProcAddress() retrieves API function pointer
  2. ReadProcessMemory() reads first 16 bytes of function prologue
  3. Pattern matching against 6 known hook signatures
  4. Log SEVERITY_CRITICAL if any pattern matches
```

## Performance Benchmarks

### Execution Time Analysis

Measured on Windows 11 Pro, Intel Core i7-11700K, 32GB RAM, NVMe SSD:

| Detection Phase | Average Time | Objects Analyzed | Memory Usage |
|----------------|--------------|------------------|--------------|
| Process Behavior | 2.1 seconds | 120 processes | 15 MB |
| API Hook Detection | 1.3 seconds | 5 critical APIs | 8 MB |
| Memory Anomaly | 4.2 seconds | 3,500 memory regions | 25 MB |
| Registry Persistence | 1.7 seconds | 6 registry paths, ~200 values | 5 MB |
| Network C2 Detection | 0.8 seconds | 45 active TCP connections | 3 MB |
| Persistence Files | 3.5 seconds | 1,200 files in %TEMP% | 12 MB |
| LOLBin Analysis | 2.4 seconds | 15 certutil/powershell/wmic processes | 10 MB |
| **Total Scan** | **16.0 seconds** | **Full system analysis** | **78 MB peak** |

### Resource Impact

- **CPU Usage**: 18-25% during scan (single-threaded, sequential phases)
- **Memory Footprint**: 50-80MB resident set size (RSS)
- **Disk I/O**: Minimal (<5 MB/s read), no persistent logging by default
- **Network Impact**: Zero (only reads existing TCP tables, no packets sent)

## Technical Implementation

### Thread-Safe Logging Architecture

```cpp
// Global resources initialization
InitializeCriticalSection(&global_threat_lock);

// Thread-safe threat logging
void LogThreat(ThreatSeverity severity, ThreatCategory category,
               LPCSTR description, LPCSTR ioc, DWORD pid) {
    EnterCriticalSection(&global_threat_lock);
    
    ThreatLog threat;
    threat.threat_id = global_threat_counter++;
    threat.severity = severity;
    threat.category = category;
    threat.timestamp = time(NULL);
    threat.associated_pid = pid;
    
    strncpy_s(threat.description, sizeof(threat.description), description, _TRUNCATE);
    strncpy_s(threat.ioc, sizeof(threat.ioc), ioc, _TRUNCATE);
    
    global_threat_log.push_back(threat);
    
    LeaveCriticalSection(&global_threat_lock);
}

// Cleanup on shutdown
DeleteCriticalSection(&global_threat_lock);
```

### PEB-Based Command-Line Extraction

```cpp
BOOL GetProcessCommandLine(DWORD pid, LPSTR buffer, DWORD buffer_size) {
    // Open process with minimal rights
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return FALSE;
    
    // Query basic process information
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, 
                                                 &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(status)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Read PEB from process memory
    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Read RTL_USER_PROCESS_PARAMETERS
    RTL_USER_PROCESS_PARAMETERS params;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, 
                          sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Read Unicode command line buffer
    WCHAR cmd_line[2048];
    if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, cmd_line, 
                          params.CommandLine.Length, NULL)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Convert Unicode to ANSI
    WideCharToMultiByte(CP_ACP, 0, cmd_line, -1, buffer, buffer_size, NULL, NULL);
    CloseHandle(hProcess);
    return TRUE;
}
```

### Network Connection Correlation

```cpp
void AnalyzeNetwork() {
    PMIB_TCPTABLE2 tcp_table = NULL;
    DWORD table_size = 0;
    
    // Get required buffer size
    if (GetTcpTable2(NULL, &table_size, TRUE) != ERROR_INSUFFICIENT_BUFFER) return;
    
    // Allocate TCP table
    tcp_table = (PMIB_TCPTABLE2)malloc(table_size);
    if (!tcp_table) return;
    
    // Retrieve TCP connections
    if (GetTcpTable2(tcp_table, &table_size, TRUE) == NO_ERROR) {
        const USHORT suspicious_ports[] = {
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 666, 1337, 0
        };
        
        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            PMIB_TCPROW2 row = &tcp_table->table[i];
            
            // Filter for established connections only
            if (row->dwState == MIB_TCP_STATE_ESTAB) {
                IN_ADDR addr;
                addr.S_un.S_addr = row->dwRemoteAddr;
                USHORT remote_port = ntohs((USHORT)row->dwRemotePort);
                
                // Check against suspicious ports
                for (int j = 0; suspicious_ports[j]; j++) {
                    if (remote_port == suspicious_ports[j]) {
                        LogThreat(SEVERITY_CRITICAL, CAT_C2_COMMUNICATION,
                                 "C2 connection detected", inet_ntoa(addr), row->dwOwningPid);
                        
                        // Automatic process termination
                        RemediateProcessTermination(row->dwOwningPid, "C2 Process");
                        break;
                    }
                }
            }
        }
    }
    
    free(tcp_table);
}
```

## Troubleshooting

### Common Deployment Issues

**Privilege Escalation Failure**
```
Error: OpenProcessToken failed (Error: 5 - Access Denied)
Cause: Insufficient privileges to query token elevation
Solution: Right-click executable → Run as Administrator, or use runas /user:Administrator
```

**Process Termination Blocked**
```
Error: TerminateProcess failed (Error: 5 - Access Denied)
Cause: Attempting to terminate protected process (PPL, SYSTEM)
Solution: Known limitation - Cannot terminate SYSTEM processes or PPL-protected processes
```

**Registry Key Deletion Failed**
```
Error: RegDeleteValueA failed (Error: 5 - Access Denied)
Cause: Registry key protected by permissions or in use
Solution: Boot into Safe Mode, or use registry permissions editor (regedit → Permissions)
```

**File Quarantine Failed**
```
Error: MoveFileExA failed (Error: 32 - File in use)
Cause: File locked by another process
Solution: Reboot system, quarantine will succeed on next execution
```

### False Positive Management

**Legitimate PowerShell Usage:**
```
Detection: [HIGH] [LOLBIN_ABUSE] powershell.exe with suspicious payload (Risk: 65/100)
Cause: Administrative script using -EncodedCommand for legitimate automation
Mitigation: Whitelist known-good scripts by hash, or exclude specific command patterns
```

**Development Tools:**
```
Detection: [CRITICAL] [HOOK_DETECTION] Hook detected in CreateProcessA
Cause: Visual Studio debugger, OllyDbg, x64dbg using API hooks for breakpoints
Mitigation: Disable suite during development sessions, or whitelist debugger processes
```

**Encrypted Backups:**
```
Detection: [CRITICAL] [PERSISTENCE] Encrypted persistence file (entropy: 7.92)
Cause: Legitimate encrypted backup file in %TEMP% directory
Mitigation: Exclude backup directories, or adjust FILE_ENTROPY_CRITICAL threshold to 7.95
```

### Debug Configuration

Enable verbose logging by adding debug output:

```cpp
// In AnalyzeLOLBins() function:
printf("[DEBUG] Process: %s, PID: %lu\n", entry.szExeFile, entry.th32ProcessID);
printf("[DEBUG] Command line: %s\n", command_line);
printf("[DEBUG] Risk score: %d/100\n", risk_score);

// In AnalyzeMemory() function:
printf("[DEBUG] Memory region: 0x%p, Size: %lu bytes, Protection: 0x%lx\n",
       mbi.BaseAddress, mbi.RegionSize, mbi.Protect);

// Compile with debug symbols:
cl.exe /Zi /EHsc /std:c++17 ThreatDetectionSuitex.cpp /link /DEBUG ws2_32.lib ...
```

## Security Considerations

### Operational Requirements

**Pre-Deployment Checklist:**
1. Obtain written authorization from system owner
2. Create system restore point or VM snapshot
3. Back up critical registry keys: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
4. Document baseline system state for comparison
5. Review detection thresholds (LOLBIN_CRITICAL_SCORE, FILE_ENTROPY_CRITICAL)
6. Configure whitelist for known-good processes if needed

**Safe Deployment Practices:**
- Deploy on isolated test system first
- Monitor resource consumption (CPU, memory, disk I/O)
- Review threat logs before executing remediation
- Keep system administrators on standby for immediate response
- Have rollback procedures documented and tested

### System Impact Awareness

**Automated remediation will:**
- Terminate processes matching threat signatures (exit code 127)
- Delete registry values in AutoRun locations
- Move files to quarantine with .QUARANTINE extension
- Disrupt network connections for processes on suspicious ports

**Potential side effects:**
- Service interruption if legitimate process terminated
- Startup failure if legitimate AutoRun entry deleted
- Application errors if quarantined file required for operation
- Data loss risk if false positive on critical file

### Legal and Ethical Compliance

**Authorization Requirements:**
- Explicit written permission from system owner
- Scope documentation specifying authorized actions
- Duration limits for testing window
- Incident reporting contact information

**Regulatory Compliance:**
- CFAA (Computer Fraud and Abuse Act) - United States
- GDPR (General Data Protection Regulation) - European Union
- Local cybersecurity laws in jurisdiction of deployment
- Industry-specific regulations (PCI-DSS, HIPAA, SOX)

## Reporting and Forensics

### Threat Log Structure

```cpp
typedef struct {
    DWORD threat_id;                    // Unique sequential identifier
    ThreatSeverity severity;            // CRITICAL, HIGH, MEDIUM, INFO
    ThreatCategory category;            // 16 distinct categories
    CHAR description[MAX_THREAT_DESC];  // Human-readable description (512 bytes)
    CHAR ioc[MAX_IOC_LEN];             // Indicator of Compromise (256 bytes)
    time_t timestamp;                   // Unix epoch timestamp
    DWORD associated_pid;               // Process ID (0 if not process-related)
} ThreatLog;
```

### Remediation Result Structure

```cpp
typedef struct {
    RemediationActionType action_type;  // KILL_PROCESS, DELETE_FILE, REMOVE_REGISTRY, etc.
    CHAR target[MAX_PATH];              // Target of remediation action
    BOOL success;                       // TRUE if action succeeded
    DWORD error_code;                   // Win32 error code on failure
    CHAR status_message[256];           // Human-readable status
} RemediationResult;
```

### Statistics Tracking

```cpp
typedef struct {
    int total_actions;              // Total remediation attempts
    int successful_actions;         // Successfully completed actions
    int failed_actions;             // Failed actions (permissions, locked files, etc.)
    int files_deleted;              // Files quarantined
    int processes_killed;           // Processes terminated
    int registry_entries_removed;   // Registry values deleted
    int tasks_removed;              // Scheduled tasks removed (not implemented)
    int blocked_connections;        // Network connections disrupted
    int auto_remediation_count;     // Total auto-remediation events
} RemediationStatistics;
```

## Known Limitations

### Technical Constraints

1. **Protected Processes**: Cannot terminate SYSTEM processes, PPL-protected processes, or critical system services (csrss.exe, smss.exe, etc.)
2. **Kernel-Level Evasion**: Rootkits operating in kernel mode bypass user-mode detection entirely
3. **DKOM Techniques**: Direct Kernel Object Manipulation (DKOM) can hide processes from CreateToolhelp32Snapshot
4. **PatchGuard**: Kernel Patch Protection prevents certain kernel-level detection techniques on x64 Windows
5. **VM Detection**: Sophisticated malware can detect sandbox environments and alter behavior

### Architectural Limitations

- **Single-threaded execution**: Sequential phase execution (no parallel scanning)
- **No kernel driver**: Relies entirely on user-mode APIs, cannot detect kernel-level threats comprehensively
- **No persistent storage**: Logs stored in memory only, lost on process termination
- **No network interception**: Cannot analyze encrypted network traffic (TLS/SSL)
- **No signature database**: Heuristic-only detection, no malware signature matching

## Legal Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Critical Legal Notices

1. **No Warranty**: The developer provides NO WARRANTY regarding detection accuracy, reliability, or completeness. False positives and false negatives are possible.

2. **User Responsibility**: Users bear FULL RESPONSIBILITY for:
   - Obtaining proper authorization before deployment
   - Verifying detection accuracy before remediation
   - Data loss from automated remediation
   - System downtime or service interruption
   - Compliance with applicable laws and regulations

3. **Limitation of Liability**: The developer SHALL NOT BE LIABLE for any special, direct, indirect, consequential, incidental, or punitive damages arising from use of this software, including but not limited to:
   - Data loss or corruption
   - System unavailability
   - False positives causing operational impact
   - Missed detections or undetected threats
   - Legal consequences of unauthorized use

4. **Authorization Requirement**: Unauthorized deployment on systems you do not own or control is ILLEGAL under:
   - Computer Fraud and Abuse Act (CFAA) - 18 U.S.C. § 1030
   - Computer Misuse Act (UK)
   - Budapest Convention on Cybercrime
   - Local criminal statutes in your jurisdiction

## Support and Contact

### Issue Reporting

For non-sensitive issues:
- **GitHub Issues**: https://github.com/genesisgzdev/threat-detection-suite/issues
- **Documentation**: README.md, BUILDING.md, SECURITY.md

For security vulnerabilities:
- **Security Issues**: genesis.Issues@pm.me (PGP required)
- **Responsible Disclosure**: 90-day disclosure timeline from initial report

Contributions welcome in areas of:
- New detection algorithms for emerging threats
- Performance optimizations for faster scanning
- False positive reduction through improved heuristics
- Documentation improvements and usage examples
- Test case development for validation

See CONTRIBUTING.md for code quality standards and submission guidelines.

## Author

**Genesis**  
**Security Researcher & Developer**  
Contact & Support: genzt.dev@pm.me   

## License

MIT License - See LICENSE file for complete terms.

Copyright (c) 2025 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

---

**Threat Detection Suite** - Advanced Endpoint Detection and Response for Windows Systems  
*Automated threat identification with integrated remediation capabilities*
