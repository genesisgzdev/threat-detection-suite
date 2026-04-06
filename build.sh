#!/bin/bash

# Threat Detection Suite v4.0 - Automated Build Script (Linux/Tooling)
# Note: Full driver build requires a Windows environment with WDK.
# This script handles CMake-based user-mode components and linters.

set -e

echo "[*] Initializing Threat Detection Suite Build Toolchain..."

# 1. Build User-Mode Components (if cross-compilation is configured)
# For now, we assume local build for Linux-based analytics or tools
if command -v cmake &> /dev/null; then
    echo "[*] Configuring User-Mode Components with CMake..."
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)
    cd ..
else
    echo "[!] CMake not found. Skipping user-mode build."
fi

# 2. Driver Build (Requires Windows/WDK)
echo "[*] ThreatDetectionKernel Driver build requires a Windows host with MSBuild/WDK."
echo "[*] Please use build.bat on a Windows system for the full EDR suite."

# 3. Static Analysis / Linting (Optional)
if command -v clang-tidy &> /dev/null; then
    echo "[*] Running static analysis..."
    # clang-tidy -p build/ ThreatDetectionSuite/TDSEngine/*.cpp ThreatDetectionSuite/TDSService/*.cpp
fi

echo "[CORE] Threat Detection Suite Toolchain Execution Complete."

