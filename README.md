# Threat Detection Suite

Threat Detection Suite (TDS) is a Windows security engineering project that connects a kernel driver, a user-mode analysis service and a small SOC tooling layer.

The repository is useful for studying the contracts and failure handling around Windows telemetry. It is not presented as a finished commercial EDR and should not be installed on a production host.

[![Windows build](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/ci.yml)
[![Security audit](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/security.yml/badge.svg)](https://github.com/genesisgzdev/threat-detection-suite/actions/workflows/security.yml)
[![License](https://img.shields.io/github/license/genesisgzdev/threat-detection-suite)](LICENSE)

## Current state

The current main branch has reproducible repository checks, Windows user-mode CI, CodeQL source analysis and contract checks. A matching Windows 10/11 x64 machine with Visual Studio, WDK, Driver Verifier and an isolated test plan is still required before making claims about native driver runtime behavior.

The response pipeline starts in `observe` mode. `contain` and `terminate` are explicit modes for controlled validation only.

## Architecture

```text
kernel driver  ->  bounded event contract  ->  TDSService
       |                                      |
       +-- WFP, minifilter, process callbacks  +-- ETW-TI and heuristics
                                              |
                                  JSONL / OTLP / optional SOC bot
```

The user-mode build produces `TDSService` and `TDSBridge`. The driver is built separately through the WDK project at `ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj`.

The main pieces are:

- WFP and minifilter telemetry with explicit lifecycle cleanup
- A bounded kernel-to-user event queue and validated IOCTL buffers
- Process protection callbacks and policy authorization checks
- ETW-TI collection, entropy analysis and optional YARA support
- JSONL logging, local rotation and optional OTLP export
- PowerShell tooling for service installation and controlled diagnostics

## Build on Windows

Requirements:

- Windows 10/11 x64
- Visual Studio 2022 with Desktop development with C++
- A WDK matching the installed Windows SDK
- CMake 3.20 or newer

Build the user-mode components:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DTDS_ENABLE_YARA=OFF
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

Build the driver with the WDK toolchain:

```powershell
msbuild ThreatDetectionSuite/TDSDriver/TDSDriver.vcxproj /m /p:Configuration=Release /p:Platform=x64 /warnAsError
```

On Linux, `bash build.sh` runs repository and contract checks only. It does not compile the Windows driver.

## Configuration

- `TDS_RESPONSE_MODE=observe|alert|contain|terminate`
- `TDS_LOG_PATH` selects the JSONL output path
- `TDS_FORENSICS=1` enables critical-alert process dumps
- `TDS_ENABLE_YARA` is enabled through CMake and requires a YARA SDK

Review [BUILDING.md](BUILDING.md), [SECURITY.md](SECURITY.md) and [DISCLAIMER.md](DISCLAIMER.md) before loading a driver or enabling response actions.

## Validation boundary

The CI build proves that the checked-in contracts and Windows compilation path are coherent. It does not prove that the driver is safe on every Windows installation, that WDK signing is available, or that enforcement works correctly under real hostile input. Those checks belong on isolated hardware or a disposable VM.

## License

Apache 2.0. See [LICENSE](LICENSE).
