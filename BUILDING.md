# BUILDING: Threat Detection Suite v4.0

This guide provides instructions for building the Threat Detection Suite suite from source. The project uses a modular build process involving CMake for user-mode components and the Windows Driver Kit (WDK) for the kernel-mode driver.

## Prerequisites

- **Windows 10/11:** Required for both development and execution.
- **Visual Studio 2022:** Community, Professional, or Enterprise.
- **Windows Driver Kit (WDK):** Ensure it matches your installed Windows SDK version.
- **CMake 3.20+:** For managing the build process of user-mode components.
- **Git:** For version control.

## Build Process

### 1. Clone the Repository
```powershell
git clone https://github.com/example/threat-detection-suite-repo.git
cd threat-detection-suite-repo
```

### 2. Build User-Mode Components (Service, Engine, Scanner)
We use CMake to generate the build files for the user-mode components.

```powershell
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

The resulting binaries (e.g., `ThreatDetectionService.exe`) will be located in the `bin/Release` directory.

### 3. Build Kernel-Mode Driver (ThreatDetectionKernel)
The driver must be built using the MSBuild system provided by the WDK.

```powershell
cd ThreatDetectionSuite/TDSDriver
msbuild ThreatDetectionKernel.vcxproj /p:Configuration=Release /p:Platform=x64
```

The resulting driver file (`ThreatDetectionKernel.sys`) will be in the `x64/Release` directory.

### 4. Code Signing
Kernel-mode drivers must be signed to be loaded on 64-bit Windows systems. For development, you can use a self-signed certificate and enable Test Signing mode.

```powershell
# Enable Test Signing (Requires Reboot)
bcdedit /set testsigning on

# Sign the driver with a test certificate (Placeholder)
signtool sign /v /s PrivateCertStore /n "TDSestCert" /t http://timestamp.digicert.com x64/Release/ThreatDetectionKernel.sys
```

## Modular Build Scripts
You can also use the provided build scripts for a more automated process:

- **Windows:** `build.bat`
- **Linux (Cross-compilation/Tooling):** `build.sh` (Note: Full driver build requires Windows environment).

## Troubleshooting
- **Missing WDK:** Ensure the WDK extension for Visual Studio is installed.
- **CMake Errors:** Verify that the Windows SDK is correctly detected by CMake.
- **Driver Loading Failures:** Check the Windows Event Log or use `DbgView` for kernel-mode debug messages.
