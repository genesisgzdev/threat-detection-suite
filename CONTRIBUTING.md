# CONTRIBUTING: Threat Detection Suite v4.2.0

Welcome to the Threat Detection Suite project. Contributing to a kernel-level security tool requires rigorous engineering standards and a primary focus on system stability.

## Engineering Standards

### 1. Programming Standards
- **User-mode (Service/Engine):** Strict C++17. Leverage RAII, smart pointers, and `std::variant`/`std::optional` for safety. Avoid raw pointers.
- **Kernel-mode (Driver):** Strict C11. Adhere to WDK (Windows Driver Kit) best practices. Use NonPagedPoolNx for memory safety.
- **Naming Conventions:** PascalCase for Classes/Structs, camelCase for variables/functions, and `g_` prefix for global variables.

### 2. Kernel Programming Guidelines
- **IRQL Management:** Never call functions that require `PASSIVE_LEVEL` at `DISPATCH_LEVEL`. Use spinlocks sparingly and only for very short durations.
- **Memory Management:** Use `TDSAllocatePool` (wrapper for `ExAllocatePoolWithTag`) with tag `'SDTe'`. Rigorously verify all allocation results.
- **Inverted Call Model:** Follow the established model for user-mode communication. Never use shared events; always use pending IRPs.

### 3. Driver Debugging Guide
To contribute to driver development, you must set up a proper debugging environment:
1.  **Target Machine:** Use a Windows 10/11 Virtual Machine (VMware/Hyper-V).
2.  **Enable Debugging:** Run `bcdedit /debug on` and `bcdedit /dbgsettings net hostip:<IP> port:50000` on the VM.
3.  **Host Machine:** Use WinDbg (Preview) on your development machine.
4.  **Symbol Path:** Configure WinDbg to use Microsoft Symbol Server and your local build output folder.
5.  **DbgPrint:** Use `DbgPrint` or `KdPrint` for logging. Monitor logs using `DbgView` (Run as Admin, check "Capture Kernel").

## Development Workflow

1.  **Branching:** Create a feature branch from `main` (or `develop` if present).
2.  **Reproduction:** For bug fixes, include a reproduction script or a new unit test case.
3.  **Validation:**
    - **Unit Tests:** Located in `tests/`. Use the provided CMake test runner.
    - **Driver Validation:** Run with Static Driver Verifier (SDV) and Driver Verifier (verifier.exe) on the target machine.
4.  **Pull Request:** Ensure your code passes all linting and build checks. Provide a detailed summary of architectural changes.

By contributing, you agree that your contributions will be licensed under the project's [MIT LICENSE](LICENSE).
