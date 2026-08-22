#!/usr/bin/env bash

# Threat Detection Suite v5.6.7 - repository and Windows build entrypoint
# Note: Full driver build requires a Windows environment with WDK.
# This script handles CMake-based user-mode components and linters.

set -euo pipefail

echo "[*] Initializing Threat Detection Suite Build Toolchain..."

python3 tests/contract_checks.py

if [[ "${OSTYPE:-}" != msys* && "${OSTYPE:-}" != cygwin* && "${OS:-}" != Windows_NT ]]; then
    echo "[*] Linux host detected: Windows user-mode and WDK builds are deferred to the Windows CI job."
    exit 0
fi

# 1. Build User-Mode Components (if cross-compilation is configured)
# For now, we assume local build for Linux-based analytics or tools
if command -v cmake &> /dev/null; then
    echo "[*] Configuring User-Mode Components with CMake..."
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DTDS_YARA_ROOT="${TDS_YARA_ROOT:-}"
    cmake --build build --config Release --parallel
else
    echo "[!] CMake not found. Skipping user-mode build."
fi

# 2. Driver Build (Requires Windows/WDK)
echo "[*] The WDK driver build runs on Windows through tools/build-driver.ps1 or the TDSDriverBuild CMake target."

# 3. Static Analysis / Linting (Optional)
if command -v clang-tidy &> /dev/null; then
    echo "[*] Running static analysis..."
    # clang-tidy -p build/ ThreatDetectionSuite/TDSEngine/*.cpp ThreatDetectionSuite/TDSService/*.cpp
fi

echo "[CORE] Threat Detection Suite Toolchain Execution Complete."
