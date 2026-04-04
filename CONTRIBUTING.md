# CONTRIBUTING: Threat Detection Suite v4.0

Welcome to the Threat Detection Suite project. Contributing to a kernel-level security tool requires rigorous engineering standards and a focus on system stability.

## Engineering Standards

### 1. Programming Standards
- **User-mode (Service/Engine):** Strict C++17. Use modern C++ features (RAII, smart pointers) and avoid raw pointers where possible.
- **Kernel-mode (Driver):** Strict C11. Adhere to WDK (Windows Driver Kit) best practices.
- **Code Style:** Follow the `.editorconfig` settings (Allman style, 4-space indentation).
- **Naming Conventions:** Use PascalCase for classes/structs and camelCase for variables/functions.

### 2. Kernel Programming Guidelines
- **IRQL Management:** Always be aware of the IRQL (Interrupt Request Level). Do not call functions that require `PASSIVE_LEVEL` at `DISPATCH_LEVEL` or higher.
- **Memory Management:** Use `ExAllocatePool2` (or `ExAllocatePoolWithTag` for older versions) with appropriate pool tags. Always free allocated memory in all exit paths.
- **Error Handling:** Check all `NTSTATUS` return values. Use `NT_SUCCESS()` macro.
- **Stability:** Kernel crashes (BSOD) are unacceptable. Thoroughly test all driver changes in a virtualized environment with a debugger attached.

### 3. Behavioral Correlation & ETW
- When adding new detection logic to `TDSEngine`, ensure it is modular and well-documented.
- ETW event consumers should be efficient to minimize system overhead.

## Development Workflow

1.  **Fork and Branch:** Create a feature branch from the `develop` branch.
2.  **Implementation:** Implement your changes, following the standards above.
3.  **Testing:**
    - **Unit Tests:** Add unit tests for user-mode logic in the `tests/` directory.
    - **Integration Tests:** Verify driver-service communication and end-to-end detection.
4.  **Documentation:** Update the relevant documentation if you change or add functionality.
5.  **Pull Request:** Submit a PR to the `develop` branch. PRs must pass all CI checks and require approval from at least two maintainers.

## Code Reviews
Code reviews are intensive. Expect feedback on:
- Security implications.
- Performance impact (especially in the kernel driver).
- Adherence to architectural patterns.
- Error handling and edge cases.

By contributing, you agree that your contributions will be licensed under the project's [LICENSE](LICENSE).
