# BUILDING: Threat Detection Suite v5.6.5

This guide provides instructions for building the Threat Detection Suite suite from source. The project uses a modular build process involving CMake for user-mode components and the Windows Driver Kit (WDK) for the kernel-mode driver.

## Prerequisites

- **Windows 10/11 (x64):** Required for both development and execution.
- **Visual Studio 2022:** With "Desktop development with C++" and "Windows Driver Kit" components.
- **Windows Driver Kit (WDK):** Must match your installed Windows SDK version.
- **CMake 3.20+:** For managing the build process of user-mode components.
- **Git:** For version control.

## Build Process

### 1. Clone the Repository
```powershell
git clone https://github.com/genesisgzdev/threat-detection-suite.git
cd threat-detection-suite
```

### 2. Build User-Mode Components (Service, Engine, Scanner)
We use CMake to generate the build files for the user-mode components.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DTDS_ENABLE_YARA=OFF
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

The resulting binaries (e.g., `TDSService.exe`) will be located in the `bin/Release` directory.

### 3. Build Kernel-Mode Driver (ThreatDetectionKernel)
The driver must be built using the MSBuild system provided by the WDK.

```powershell
msbuild ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj /m /p:Configuration=Release /p:Platform=x64 /warnAsError
```

The resulting driver file (`ThreatDetectionKernel.sys`) will be in the `x64/Release` directory.

### 4. Code Signing
Kernel-mode drivers must be signed to be loaded on 64-bit Windows systems. For development, use a test certificate and enable Test Signing mode.

```powershell
# Enable Test Signing (Requires Administrator and Reboot)
bcdedit /set testsigning on

# Sign the driver with your test certificate
# Replace "TDSTestCert" with the actual name of your certificate
signtool sign /v /s PrivateCertStore /n "TDSTestCert" /t http://timestamp.digicert.com x64/Release/ThreatDetectionKernel.sys
```

## Modular Build Scripts
You can also use the provided build scripts for an automated process:

- **Windows:** `powershell -ExecutionPolicy Bypass -File tools/build-driver.ps1` builds the WDK project.
- **Linux:** `bash build.sh` runs shared-ABI and repository checks; full user-mode/driver builds require Windows.

## Response modes

TDS starts in `observe` mode. Set `TDS_RESPONSE_MODE=contain` only in an isolated
validation host after reviewing events. `terminate` is reserved for controlled
tests and requires the highest score threshold. The driver always receives the
same policy so kernel enforcement cannot silently diverge from user-mode policy.

## Troubleshooting
- **Missing WDK:** If MSBuild fails to find driver targets, reinstall the WDK and the Visual Studio extension.
- **CMake Errors:** Ensure `WIN32_LEAN_AND_MEAN` is handled correctly if adding new dependencies.
- **Driver Loading Failures:** Check `DbgView` (with "Capture Kernel" enabled) for status messages from `TDS: Kernel Gateway`.
