# Contributing to Threat Detection Suite (TDS)

We welcome technical contributions that push the boundaries of event-driven security.

## 🛠 Engineering Standards

### Languages & Dialects
-   **User-Mode Engine**: Strictly **C++17**. We leverage modern RAII, filesystem, and template metaprogramming.
-   **Kernel-Mode Core**: Strictly **C11** (MSVC/WDK compatible). No GNU extensions that break cross-compiler compatibility for driver development.

### 🚫 The "Zero Polling" Mandate
TDS is a 100% **Event-Driven** framework. Any contribution that introduces polling (e.g., `while(true) { sleep(100); check_status(); }`) will be **rejected automatically**. 
- Use **Kernel Callbacks** (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`).
- Use **WFP Callouts** for network.
- Use **Minifilter** for I/O.
- Use **ETW-Ti** for advanced threat intelligence telemetry.

## 🚀 Contribution Workflow

1.  **Architecture Alignment**: Before writing complex code, open a "Design Proposal" issue to discuss the implementation strategy.
2.  **VM Testing**: All kernel-mode changes MUST be verified using **Driver Verifier** and tested in a VM against various Windows 10/11 builds.
3.  **Security Audit**: Run local Snyk and OSV-Scanner checks:
    ```bash
    # Check for vulnerable dependencies
    osv-scanner --recursive .
    # Perform static analysis
    snyk code test
    ```
4.  **Pull Request**: Provide a detailed description of the changes and the evidence of successful testing (logs/dumps).

## 🖋 Style Guide
- Use **PascalCase** for Classes/Structs and **camelCase** for members/functions.
- Prefer `std::unique_ptr` and `std::shared_ptr` in user-mode; manual memory management in kernel-mode must be handled with strict `ExAllocatePool2` / `ExFreePool` cycles.
- All sensitive strings must be encrypted/obfuscated at compile time.

## ⚖️ License
By contributing to TDS, you agree that your code will be released under the [Apache License 2.0](LICENSE).
