# Contributing to Threat Detection Suite

## Overview

Contributions to this project must maintain production-grade code quality and adhere to strict implementation standards. This is a professional security tool, not a learning project or proof-of-concept.

## Core Principles

### Real Implementations Only

Every line of code must serve a concrete purpose:

- **No generic utilities**: Every function must address a specific threat detection or remediation scenario
- **No placeholder code**: All implementations must be production-ready and fully functional
- **No mock functions**: All Windows API calls must be real, tested, and operational
- **No decorative output**: Console output must be actionable information only

### Production-Grade Standards

All code contributions require:

- Functional Windows API implementations with proper error handling
- Resource cleanup on all execution paths (handles, memory, critical sections)
- Input validation at function entry points
- Secure string operations (strcpy_s, strncpy_s, snprintf with bounds)
- Self-documenting code with minimal comments

## Development Workflow

### 1. Branch Creation

```bash
git checkout -b feature/threat-detection-enhancement
```

Use descriptive branch names that indicate the security capability being added.

### 2. Implementation Requirements

Before writing code, ensure:

- The feature addresses a real threat detection gap
- Windows API documentation has been reviewed
- Error handling strategy is defined
- Resource cleanup requirements are understood

### 3. Build Verification

Test compilation on multiple toolchains:

```bash
# Windows (MSVC)
build.bat

# Unix/Linux (GCC/Clang)
./build.sh

# CMake (cross-platform)
mkdir build && cd build
cmake .. && cmake --build .
```

### 4. Testing Protocol

All contributions must pass:

- Compilation with `/W4` (MSVC) or `-Wall -Wextra -Wpedantic` (GCC/Clang)
- Execution with Administrator/root privileges
- Resource leak verification (handles, memory, critical sections)
- Edge case validation (NULL pointers, invalid handles, buffer boundaries)
- False positive rate assessment on clean systems

### 5. Pull Request Submission

Include in your PR:

- **Description**: Clear explanation of the security capability added or improved
- **Testing evidence**: Verification of detection accuracy and remediation effectiveness
- **API compatibility**: Confirmation that existing detection modules remain functional
- **Performance impact**: Assessment of CPU and memory overhead

## Code Standards

### C++ Style Guidelines

```cpp
// Correct: Clear, purposeful function
BOOL DetectAPIHook(LPCSTR api_name, HMODULE module) {
    FARPROC func = GetProcAddress(module, api_name);
    if (!func) return FALSE;
    
    BYTE prologue[16];
    if (!ReadProcessMemory(GetCurrentProcess(), func, prologue, sizeof(prologue), NULL)) {
        return FALSE;
    }
    
    // JMP instruction detection (0xE9 or 0xEB)
    if (prologue[0] == 0xE9 || prologue[0] == 0xEB) {
        return TRUE;
    }
    
    return FALSE;
}
```

**Style requirements:**
- **Indentation**: 4 spaces (no tabs)
- **Line length**: 120 characters maximum for code, 80 for comments
- **Naming**: snake_case for variables/functions, PascalCase for types
- **Braces**: K&R style (opening brace on same line)

### Windows API Best Practices

```cpp
// Always validate handles
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
    return FALSE;
}

// Always clean up resources
BYTE buffer[4096];
if (ReadProcessMemory(hProcess, addr, buffer, sizeof(buffer), NULL)) {
    // Process data
}
CloseHandle(hProcess);  // Critical: always close handles
```

**Required patterns:**
- Check all API return values
- Close all handles before function return
- Use `_s` secure functions for string operations
- Validate buffer sizes before memory operations
- Free all allocated memory on error paths

### Prohibited Patterns

**Never do this:**

```cpp
// WRONG: Generic utility function
template<typename T>
T GetValue() { return T(); }

// WRONG: Placeholder implementation
void DetectThreat() {
    printf("TODO: Implement detection\n");
}

// WRONG: Unchecked API call
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
ReadProcessMemory(h, addr, buf, size, NULL);  // No error checking!

// WRONG: Decorative output
printf("========================================\n");
printf("=     THREAT DETECTION ENGINE        =\n");
printf("========================================\n");
```

## Commit Message Format

### Structure

```
<type>: <brief description>

<detailed explanation>

Technical details:
- Specific APIs or algorithms modified
- Performance characteristics
- Known limitations or edge cases
```

### Types

- `feat`: New detection module or capability
- `fix`: Bug fix in existing detection logic
- `perf`: Performance optimization
- `refactor`: Code restructuring without behavior change
- `docs`: Documentation updates
- `build`: Build system or dependency changes

### Examples

```
feat: Add shellcode detection via NOP sled analysis

Implemented memory scanning for executable regions containing NOP sleds 
(10+ consecutive 0x90 bytes) followed by potential shellcode. Uses 
VirtualQueryEx to enumerate process memory and identifies PAGE_EXECUTE_READWRITE 
regions as high-risk indicators.

Technical details:
- Scans all committed memory pages per process
- Threshold: 10 consecutive NOPs triggers detection
- Average scan time: 2-3 seconds per process
- False positive rate: <1% on legitimate software
```

```
fix: Correct registry key deletion error handling

Fixed RemediateRegistryCleanup() to properly handle ERROR_ACCESS_DENIED 
when attempting to delete protected registry values. Function now logs 
failure with specific error code rather than silently continuing.

Technical details:
- Added explicit check for RegDeleteValueA return value
- Logs error code via GetLastError() on failure
- Updates remediation_stats.failed_actions counter
```

## Review Process

### Code Review Criteria

1. **Functional correctness**: Does the code detect/remediate the claimed threat?
2. **API usage**: Are Windows API calls used correctly with proper error handling?
3. **Resource management**: Are all handles closed and memory freed?
4. **Security impact**: Does the code introduce new attack surface?
5. **Performance**: Is the overhead acceptable for real-time detection?

### Testing Requirements

Reviewers will verify:

- Compilation on Windows 10/11 with MSVC 2019+
- Execution with Administrator privileges
- Detection accuracy on known malware samples
- False positive rate on clean systems
- Resource usage (CPU, memory, handles)

### Approval Criteria

Pull requests require:

- Passing automated build checks (if configured)
- Code review approval from maintainer
- Verification of detection capabilities
- Confirmation of zero breaking changes to existing modules

## Licensing

By submitting a pull request, you agree that your contributions will be licensed under the MIT License. All contributed code must be original work or properly attributed open-source code compatible with MIT licensing.

## Questions or Issues

For questions about contribution guidelines or clarification on implementation requirements, open an issue on the repository with the `question` label.

---

**Remember**: This is a professional security tool. Code quality standards are non-negotiable. Every contribution must meet production-grade requirements for deployment in security-critical environments.
