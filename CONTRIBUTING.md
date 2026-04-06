# Contributing to Threat Detection Suite

We welcome security researchers and developers to contribute to the suite.

## 🚀 How to Contribute

### 1. Research & Bug Reports
- Use the GitHub Issue tracker for feature requests or functional bugs.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md).

### 2. Pull Requests
- Fork the repository and create your branch from `main`.
- **Testing**: Any kernel changes MUST be tested in a dedicated VM. Ensure no BSOD occurs during common operations.
- **Coding Standard**: Adhere to C++17 for user-mode and C11 for kernel-mode logic.
- **Security Scans**: Run a local Snyk scan before submitting:
  ```bash
  snyk code test
  ```

## 📜 Development Guidelines
- **Event-Driven Only**: Polling is strictly forbidden. All detections must be based on callbacks (Kernel) or ETW (Userland).
- **Resource Management**: Strictly manage kernel pools and ensure no leaks using tools like Driver Verifier.

## ⚖️ License
By contributing to TDS, you agree that your contributions will be licensed under its [Apache License 2.0](LICENSE).
